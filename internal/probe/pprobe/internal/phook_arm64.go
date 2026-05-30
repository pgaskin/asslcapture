//go:build linux && arm64

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package phook

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type Regs = unix.PtraceRegsArm64

const instructionSize = 4

var breakpoint [instructionSize]byte = [...]byte{0x00, 0x00, 0x20, 0xD4} // brk #0

func (p *Process) handleBreakpoint(thread *threadInfo) {
	// reinstall the breakpoint after a single-step
	if bp := thread.stepping; bp != nil {
		thread.stepping = nil
		reinstallBreakpoint(thread.tid, bp.va)
		p.cont(thread, 0)
		return
	}

	var regs unix.PtraceRegsArm64
	if err := unix.PtraceGetRegSetArm64(thread.tid, unix.NT_PRSTATUS, &regs); err != nil {
		p.cont(thread, 0)
		return
	}

	bp, ok := p.bps[uintptr(regs.Pc)]
	if !ok {
		// not our breakpoint
		p.cont(thread, unix.SIGTRAP)
		return
	}

	// emit blocks until the iter body finishes, so the thread is stopped for
	// the entire duration of any reads the body performs.
	p.emit(&Breakpoint{
		PID:    p.pid,
		TID:    thread.tid,
		Path:   bp.spec.path,
		Offset: bp.spec.offset,
		Regs:   &regs,
	})

	// single-step with the original instruction
	removeBreakpoint(thread.tid, bp.va, bp.origInstr)
	thread.stepping = bp
	unix.PtraceSingleStep(thread.tid)
}

func installBreakpoint(tid int, va uintptr) (orig [instructionSize]byte, err error) {
	if _, err := unix.PtracePeekText(tid, va, orig[:]); err != nil {
		return orig, fmt.Errorf("peek at %#x: %w", va, err)
	}
	if err := reinstallBreakpoint(tid, va); err != nil {
		return orig, fmt.Errorf("poke at %#x: %w", va, err)
	}
	return orig, nil
}

func removeBreakpoint(tid int, va uintptr, orig [instructionSize]byte) error {
	_, err := unix.PtracePokeText(tid, va, orig[:])
	return err
}

func reinstallBreakpoint(tid int, va uintptr) error {
	_, err := unix.PtracePokeText(tid, va, breakpoint[:])
	return err
}
