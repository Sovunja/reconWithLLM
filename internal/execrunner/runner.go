// Package execrunner — обёртка над os/exec для запуска внешних
// инструментов разведки (subfinder, httpx, hakrawler и т.д.).
package execrunner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Spec описывает запуск внешнего бинарника.
type Spec struct {
	Bin     string            // имя бинарника, должен быть в PATH
	Args    []string          // аргументы командной строки
	Env     map[string]string // дополнительные переменные окружения
	Timeout time.Duration     // жёсткий таймаут (0 = без таймаута, только ctx)

	// OnLine вызывается на каждую строку stdout (для NDJSON-вывода).
	// Если не задан — stdout копится в Result.Stdout.
	OnLine func(line []byte)

	// OnStderr вызывается на каждую строку stderr. Полезно для прогресса:
	// многие тулзы (katana, nuclei) пишут диагностику именно в stderr.
	// Если не задан — stderr копится в Result.Stderr.
	OnStderr func(line []byte)

	// Stdin — данные, которые будут переданы процессу на stdin.
	// Используется тулзами вроде httpx, которые читают список целей из stdin.
	Stdin string
}

// Result — итог запуска.
type Result struct {
	ExitCode int
	Stdout   []byte // если OnLine не задан
	Stderr   []byte
	Duration time.Duration
}

// Run запускает процесс по спецификации.
func Run(ctx context.Context, spec Spec) (*Result, error) {
	if spec.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, spec.Timeout)
		defer cancel()
	}

	cmd := exec.Command(spec.Bin, spec.Args...)

	// Запускаем процесс в новой process group, чтобы при отмене убить
	// весь поддерево — например, katana порождает headless-браузер.
	// Без этого дочерние процессы остаются жить после Kill().
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Прокидываем окружение.
	if len(spec.Env) > 0 {
		env := make([]string, 0, len(spec.Env))
		for k, v := range spec.Env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = append(cmd.Environ(), env...)
	}

	// stdout: либо потоково через OnLine, либо копим в буфер.
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	// stderr: тоже через pipe — чтобы стримить прогресс тулзов в реальном
	// времени. Многие тулзы пишут диагностику в stderr (katana с -v, nuclei).
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	// stdin: для тулзов, читающих список целей со стандартного ввода (httpx).
	if spec.Stdin != "" {
		cmd.Stdin = strings.NewReader(spec.Stdin)
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", spec.Bin, err)
	}

	// Watcher: если ctx отменён или истёк таймаут — мягко гасим всю group.
	doneCh := make(chan struct{})
	var killWG sync.WaitGroup
	killWG.Add(1)
	go func() {
		defer killWG.Done()
		select {
		case <-doneCh:
			return
		case <-ctx.Done():
			// SIGTERM всей process group (отрицательный PID = group).
			pgid, err := syscall.Getpgid(cmd.Process.Pid)
			if err == nil {
				_ = syscall.Kill(-pgid, syscall.SIGTERM)
			}
			// Если за 5 сек не умер — SIGKILL.
			select {
			case <-doneCh:
			case <-time.After(5 * time.Second):
				if err == nil {
					_ = syscall.Kill(-pgid, syscall.SIGKILL)
				}
			}
		}
	}()

	// Чтение stdout и stderr — параллельно в отдельных горутинах.
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	var ioWG sync.WaitGroup
	ioWG.Add(2)

	go func() {
		defer ioWG.Done()
		var dst io.Writer = stdoutBuf
		if spec.OnLine != nil {
			dst = io.Discard
		}
		_ = streamLines(stdoutPipe, dst, spec.OnLine)
	}()

	go func() {
		defer ioWG.Done()
		var dst io.Writer = stderrBuf
		if spec.OnStderr != nil {
			dst = io.Discard
		}
		_ = streamLines(stderrPipe, dst, spec.OnStderr)
	}()

	ioWG.Wait()           // дожидаемся EOF на обоих пайпах
	waitErr := cmd.Wait() // потом собираем статус процесса
	close(doneCh)
	killWG.Wait()

	res := &Result{
		ExitCode: cmd.ProcessState.ExitCode(),
		Stdout:   stdoutBuf.Bytes(),
		Stderr:   stderrBuf.Bytes(),
		Duration: time.Since(start),
	}

	// Различаем три исхода:
	//   - ctx истёк/отменён: возвращаем ctx.Err() (DeadlineExceeded/Canceled),
	//     вызывающий код может проверить через errors.Is.
	//   - exit code != 0: возвращаем *exec.ExitError, чтобы адаптер мог
	//     решить, ошибка это или штатная ситуация (см. nuclei).
	//   - всё ок: nil.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return res, ctxErr
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return res, exitErr
		}
		return res, fmt.Errorf("%s wait: %w", spec.Bin, waitErr)
	}
	return res, nil
}

// streamLines читает поток построчно. Если задан onLine — вызывает его
// на каждую строку; иначе копирует всё в dst.
func streamLines(r io.Reader, dst io.Writer, onLine func([]byte)) error {
	scanner := bufio.NewScanner(r)
	// По умолчанию bufio.Scanner ограничен 64 KiB на строку — для NDJSON
	// от nuclei этого может не хватить. Поднимаем до 1 MiB.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if onLine != nil {
			// Копируем срез: scanner переиспользует буфер на следующей итерации.
			cp := make([]byte, len(line))
			copy(cp, line)
			onLine(cp)
		} else {
			_, _ = dst.Write(append(line, '\n'))
		}
	}
	return scanner.Err()
}
