//go:build linux
// +build linux

package ptrace

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/slimtoolkit/slim/pkg/errors"
	"github.com/slimtoolkit/slim/pkg/launcher"
	"github.com/slimtoolkit/slim/pkg/mondel"
	"github.com/slimtoolkit/slim/pkg/report"
	"github.com/slimtoolkit/slim/pkg/system"
)

type syscallEvent struct {
	callNum uint32
	retVal  uint64
}

const (
	eventBufSize = 500
	ptOptions    = unix.PTRACE_O_TRACESYSGOOD | // flag syscall-stops with SIGTRAP|0x80 signal
		unix.PTRACE_O_EXITKILL |
		//	unix.PTRACE_O_TRACECLONE |
		/*
			The O_TRACEFORK, O_TRACEVFORK, O_TRACECLONE, O_TRACEVFORKDONE
			have different behaviors, which is not so clearly documented in
			https://man7.org/linux/man-pages/man2/ptrace.2.html:

			O_TRACEFORK - will cause to start tracing new process automatically,
			PtraceGetEventMsg will return the child PID, child continues without SIGSTOP(!)

			O_TRACEVFORK - will also case tracing of the new process, but
			PtraceGetEventMsg will return the pid of the process that called VFORK/CLONE
			child will receive SIGSTOP, as stated in the manual

			O_TRACECLONE - investigating. glibc wrappers for fork(), vfork() actually call clone3()
			with various flags to achieve desired effect. The child is not receiving SIGSTOP, though.

			O_TRACEVFORKDONE - will not cause tracing of the new process

			So 2 events actually happen, with PtraceSyscall + Wait4 in between:
			1. syscall entry stop at `clone`, etc
			2. corresponding PTRACE_EVENT_*, delivered via SIGTRAP

			and in case of O_TRACEVFORK, the 3rd event will follow:
			3. a group stop  (SIGSTOP), which allows ptrace'ing the new child process!
		*/
		unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACEVFORKDONE |
		unix.PTRACE_O_TRACECLONE |
		unix.PTRACE_O_TRACEEXIT

	traceSysGoodStatusBit = 0x80
	SIGPTRAP              = syscall.SIGTRAP | traceSysGoodStatusBit
)

type status struct {
	report *report.PtMonitorReport
	err    error
}

// track tracing state of all child processes
type ptraceState struct {
	pid          int
	callNum      uint64
	callName     string
	retVal       uint64
	expectReturn bool
	gotCallNum   bool
	gotRetVal    bool
	started      bool
	exiting      bool
	pathParam    string
	pathParamErr error
}

type monitor struct {
	ctx    context.Context
	cancel context.CancelFunc

	del mondel.Publisher

	artifactsDir string

	runOpt AppRunOpt

	// TODO: Move the logic behind these two fields to the artifact processig stage.
	includeNew bool
	origPaths  map[string]struct{}

	// To receive signals that should be delivered to the target app.
	signalCh <-chan os.Signal

	status status
	doneCh chan struct{}
}

func NewMonitor(
	ctx context.Context,
	del mondel.Publisher,
	artifactsDir string,
	runOpt AppRunOpt,
	includeNew bool,
	origPaths map[string]struct{},
	signalCh <-chan os.Signal,
	errorCh chan<- error,
) Monitor {
	ctx, cancel := context.WithCancel(ctx)
	return &monitor{
		ctx:    ctx,
		cancel: cancel,

		del: del,

		artifactsDir: artifactsDir,

		runOpt: runOpt,

		includeNew: includeNew,
		origPaths:  origPaths,

		signalCh: signalCh,

		doneCh: make(chan struct{}),
	}
}

func (m *monitor) Start() error {
	logger := log.WithField("op", "sensor.pt.monitor.Start")
	logger.Info("call")
	defer logger.Info("exit")

	logger.WithFields(log.Fields{
		"name": m.runOpt.Cmd,
		"args": m.runOpt.Args,
	}).Debug("starting target app...")

	sysInfo := system.GetSystemInfo()
	archName := system.MachineToArchName(sysInfo.Machine)
	syscallResolver := system.CallNumberResolver(archName)

	appName := m.runOpt.Cmd
	appArgs := m.runOpt.Args
	workDir := m.runOpt.WorkDir
	appUser := m.runOpt.User
	runTargetAsUser := m.runOpt.RunAsUser
	rtaSourcePT := m.runOpt.RTASourcePT
	// TODO(ivan): Implement the runOpt.ReportOnMainPidExit handling.

	// The sync part of the start was successful.

	// Starting the async part...
	go func() {
		logger := log.WithField("op", "sensor.pt.monitor.processor")
		logger.Debug("call")
		defer logger.Debug("exit")

		ptReport := &report.PtMonitorReport{
			ArchName:     string(archName),
			SyscallStats: map[string]report.SyscallStatInfo{},
		}

		syscallStats := map[uint32]uint64{}
		eventChan := make(chan syscallEvent, eventBufSize)
		collectorDoneChan := make(chan int, 1)

		var app *exec.Cmd

		go func() {
			logger := log.WithField("op", "sensor.pt.monitor.collector")
			logger.Debug("call")
			defer logger.Debug("exit")

			//IMPORTANT:
			//Ptrace is not pretty... and it requires that you do all ptrace calls from the same thread
			runtime.LockOSThread()

			var err error
			app, err = launcher.Start(
				appName,
				appArgs,
				workDir,
				appUser,
				runTargetAsUser,
				rtaSourcePT,
				m.runOpt.AppStdout,
				m.runOpt.AppStderr,
			)
			if err != nil {
				m.status.err = errors.SE("sensor.ptrace.Run/launcher.Start", "call.error", err)
				close(m.doneCh)
				return
			}

			// TODO: Apparently, rtaSourcePT is ignored by this below code.
			//       The x86-64 version of it has an alternative code branch
			//       to run the target app w/o tracing.

			cancelSignalForwarding := startSignalForwarding(m.ctx, app, m.signalCh)
			defer cancelSignalForwarding()

			targetPid := app.Process.Pid

			//pgid, err := syscall.Getpgid(targetPid)
			//if err != nil {
			//	log.Warnf("ptmon: collector - getpgid error %d: %v", targetPid, err)
			//	collectorDoneChan <- 1
			//	return
			//}

			logger.Debugf("target PID ==> %d", targetPid)

			var wstat unix.WaitStatus

			pid, err := unix.Wait4(targetPid, &wstat, 0, nil)
			if err != nil {
				logger.Warnf("unix.Wait4 - error waiting for %d: %v", targetPid, err)
				collectorDoneChan <- 2
				return
			}
			if pid != targetPid {
				logger.Tracef("wait4 returned new pid(%d), expected(%d)", pid, targetPid)
			}

			err = syscall.PtraceSetOptions(targetPid, ptOptions)
			if err != nil {
				log.Warnf("ptmon: collector - error setting trace options %d: %v", targetPid, err)
				collectorDoneChan <- 3
				return
			}

			logger.Debugf("initial process status = %v (pid=%d)", wstat, pid)

			/*
				syscallReturn := false
				gotCallNum := false
				gotRetVal := false
				var callName string
				var callNum uint64
				var retVal uint64
			*/
			var procState map[int]*ptraceState = make(map[int]*ptraceState)

			procState[targetPid] = &ptraceState{pid: targetPid, started: true}
			for {
				var childState *ptraceState
				if state, ok := procState[pid]; !ok {
					procState[pid] = &ptraceState{pid: pid}
				} else {
					childState = state
				}

				if wstat.Exited() {
					if pid == targetPid {
						logger.Warn("app exited (unexpected)")
						collectorDoneChan <- 4
						break
					}
					logger.Tracef("[pid %d] - exited", pid)
					delete(procState, pid)
					continue
				}
				if wstat.Signaled() {
					logger.Warn("[pid %d]  - signalled (unexpected)", pid)
					//collectorDoneChan <- 5
					continue
				}
				if wstat.Continued() {
					logger.Tracef("[pid %d] - continued", pid)
					continue
				}

				if !wstat.Stopped() {
					logger.Debugf("[pid %d] - bad state, should be stopped!", pid)
					continue
				}

				var stopType string
				stopSig := wstat.StopSignal()

				switch stopSig {

				case SIGPTRAP:
					stopType = "syscall_stop"

				case syscall.SIGTRAP:
					switch trapCause := wstat.TrapCause(); trapCause {
					case syscall.PTRACE_EVENT_CLONE,
						syscall.PTRACE_EVENT_FORK,
						syscall.PTRACE_EVENT_VFORK,
						syscall.PTRACE_EVENT_VFORK_DONE,
						syscall.PTRACE_EVENT_EXEC,
						syscall.PTRACE_EVENT_EXIT:
						stopType = "ptrace_event_stop"
						// previous syscall (e.g. clone) happened
						// but will not be ended in a normal cycle
						childState.expectReturn = false
						childState.gotRetVal = true

					case syscall.PTRACE_EVENT_SECCOMP:
						stopType = "seccomp_stop"
					default:
						logger.Tracef("unknown ptrace event stop (%d)...", trapCause)
						stopType = fmt.Sprintf("ptrace_%d_event", trapCause)
					}
				// these signals follow FORK for child processes, etc if ptracing clone, fork, etc
				case syscall.SIGSTOP,
					syscall.SIGTSTP,
					syscall.SIGTTIN,
					syscall.SIGTTOU:
					// these are to be ignored. this is not a debugger.
					stopType = "group_stop"
				default:
					stopType = "signal_stop"
				}

				logger.Tracef(
					"stopSig=%d (%s), stop type => %v, syscallReturn(%v)",
					int(stopSig), stopSig.String(),
					stopType,
					childState.expectReturn)

				var childSig = int(0)
				if stopType != "syscall_stop" {

					if stopType == "signal_stop" {
						childSig = int(stopSig)
						logger.Tracef("[pid %d] injecting signal(%d) with the next PtraceSyscall...", pid, childSig)
					}
					if stopType == "ptrace_event_stop" {
						eventPID, _ := syscall.PtraceGetEventMsg(targetPid)
						cause := wstat.TrapCause()
						logger.Tracef("[pid %d] ptrace stop occurred (%s), event pid = %d, syscall => %s, continue...", pid, PtraceEvenEnum(cause), eventPID, childState.callName)
					}
					logger.Tracef("non syscall stop, returning control to pid (%d), sig(%d)...", pid, childSig)
				} else {
					var regs unix.PtraceRegs

					if err := unix.PtraceGetRegs(pid, &regs); err != nil {
						logger.Fatalf("[pid %d] unix.PtraceGetRegs(call): %v", pid, err)
					}

					switch childState.expectReturn {
					case false:

						childState.callNum = system.CallNumber(regs)
						childState.callName = syscallResolver(uint32(childState.callNum))
						childState.expectReturn = true
						childState.gotCallNum = true

						logger.Tracef("[pid %d] %s( <unfinished...> : orig_r2=%d, r0=%d, r1=%d, r2=%d ", pid, childState.callName, regs.Orig_gpr2, regs.Gprs[0], regs.Gprs[1], regs.Gprs[2])
					case true:

						childState.retVal = system.CallReturnValue(regs)
						childState.expectReturn = false
						childState.gotRetVal = true

						logger.Tracef("[pid %d] <... %s resumed>) = %d : orig_r2=%d, r0=%d, r1=%d, r2=%d ", pid, childState.callName, childState.retVal, regs.Orig_gpr2, regs.Gprs[0], regs.Gprs[1], regs.Gprs[2])
					}

				}

				// continue execution
				err = unix.PtraceSyscall(pid, childSig)
				if err != nil {
					logger.Warnf("unix.PtraceSyscall error: %v", err)
					break
				}

				// wait for any child process to accommodate clones, forks, etc.
				pid, err = unix.Wait4(-1, &wstat, syscall.WALL, nil)
				if err != nil {
					logger.Warnf("unix.Wait4 - error waiting 4 %d: %v", pid, err)
					break
				}
				if pid != targetPid {
					logger.Tracef("wait4 returned child pid(%d), parent pid(%d)", pid, targetPid)
				}

				if childState.gotCallNum && childState.gotRetVal {
					//TODO: need to figure out what to do with unpaired syscalls
					// see above (e.g. ptrace_stops)
					// this should go away(?) if tracking all new process creation calls
					// these should be captured in under their own trap's (SIGRAP sig) cause
					childState.gotCallNum = false
					childState.gotRetVal = false

					select {
					case eventChan <- syscallEvent{
						callNum: uint32(childState.callNum),
						retVal:  childState.retVal,
					}:
					case <-m.ctx.Done():
						logger.Info("stopping...")
						return
					}
				}
			}

			logger.Infof("exiting... status=%v", wstat)
			collectorDoneChan <- 0
		}()

	done:
		for {
			select {
			case rc := <-collectorDoneChan:
				logger.Info("collector finished =>", rc)
				break done
			case <-m.ctx.Done():
				logger.Info("stopping...")
				//NOTE: need a better way to stop the target app...
				if err := app.Process.Signal(unix.SIGTERM); err != nil {
					logger.Warnf("app.Process.Signal(unix.SIGTERM) - error stopping target app => %v", err)
					if err := app.Process.Kill(); err != nil {
						logger.Warnf("app.Process.Kill - error killing target app => %v", *app)
					}
				}
				break done
			case e := <-eventChan:
				ptReport.SyscallCount++
				//logger.Tracef("syscall ==> %d (%s)", e.callNum, syscallResolver(e.callNum))

				if _, ok := syscallStats[e.callNum]; ok {
					syscallStats[e.callNum]++
				} else {
					syscallStats[e.callNum] = 1
				}
			}
		}

		logger.Debugf("executed syscall count = %d", ptReport.SyscallCount)
		logger.Debugf("number of syscalls: %v", len(syscallStats))
		for scNum, scCount := range syscallStats {
			logger.Tracef("%v", syscallResolver(scNum))
			logger.Tracef("[%v] %v = %v", scNum, syscallResolver(scNum), scCount)
			ptReport.SyscallStats[strconv.FormatInt(int64(scNum), 10)] = report.SyscallStatInfo{
				Number: scNum,
				Name:   syscallResolver(scNum),
				Count:  scCount,
			}
		}

		ptReport.SyscallNum = uint32(len(ptReport.SyscallStats))

		m.status.report = ptReport
		close(m.doneCh)
	}()

	return nil
}

func (m *monitor) Cancel() {
	m.cancel()
}

func (m *monitor) Done() <-chan struct{} {
	return m.doneCh
}

func (m *monitor) Status() (*report.PtMonitorReport, error) {
	return m.status.report, m.status.err
}

func startSignalForwarding(
	ctx context.Context,
	app *exec.Cmd,
	signalCh <-chan os.Signal,
) context.CancelFunc {
	log.Debug("ptmon: signal forwarder - starting...")

	ctx, cancel := context.WithCancel(ctx)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			case s := <-signalCh:
				log.WithField("signal", s).Debug("ptmon: signal forwarder - received signal")

				if s == syscall.SIGCHLD {
					continue
				}

				log.WithField("signal", s).Debug("ptmon: signal forwarder - forwarding signal")

				if err := app.Process.Signal(s); err != nil {
					log.
						WithError(err).
						WithField("signal", s).
						Debug("ptmon: signal forwarder - failed to signal target app")
				}
			}
		}
	}()

	return cancel
}

func SigTrapCauseInfo(cause int) string {
	if cause == -1 {
		return fmt.Sprintf("(code=%d)", cause)
	}

	causeEnum := PtraceEvenEnum(cause)
	info := fmt.Sprintf("(code=%d enum=%s)", cause, causeEnum)

	return info
}

func PtraceEvenEnum(data int) string {
	if enum, ok := ptEventMap[data]; ok {
		return enum
	} else {
		return fmt.Sprintf("(%d)", data)
	}
}

var ptEventMap = map[int]string{
	syscall.PTRACE_EVENT_CLONE:      "PTRACE_EVENT_CLONE",
	syscall.PTRACE_EVENT_EXEC:       "PTRACE_EVENT_EXEC",
	syscall.PTRACE_EVENT_EXIT:       "PTRACE_EVENT_EXIT",
	syscall.PTRACE_EVENT_FORK:       "PTRACE_EVENT_FORK",
	syscall.PTRACE_EVENT_SECCOMP:    "PTRACE_EVENT_SECCOMP",
	syscall.PTRACE_EVENT_VFORK:      "PTRACE_EVENT_VFORK",
	syscall.PTRACE_EVENT_VFORK_DONE: "PTRACE_EVENT_VFORK_DONE",
}
