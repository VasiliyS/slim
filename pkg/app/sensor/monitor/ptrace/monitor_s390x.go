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
	pid     int
	callNum uint32
	retVal  uint64
}

const (
	eventBufSize = 500
	ptOptions    = unix.PTRACE_O_TRACESYSGOOD | // flag syscall-stops with SIGTRAP|0x80 signal
		unix.PTRACE_O_EXITKILL |
		/*
			The O_TRACEFORK, O_TRACEVFORK, O_TRACECLONE, O_TRACEVFORKDONE
			have different behaviors, which is not so clearly documented in
			https://man7.org/linux/man-pages/man2/ptrace.2.html:

			O_TRACEFORK - will cause to start tracing new process automatically,
			PtraceGetEventMsg will return the child PID

			O_TRACEVFORK - will also case tracing of the new process, but
			PtraceGetEventMsg will return the pid of the process that called VFORK/CLONE
			child will receive SIGSTOP, as stated in the manual

			O_TRACECLONE - glibc wrappers for fork() actually call clone3()
			with a specific set of  flags to achieve desired effect
			Child will receive SIGSTOP, as stated in the manual

			O_TRACEVFORKDONE - will not cause tracing of the new process

			So the following events actually happen, with PtraceSyscall + Wait4 in between each event:
			1. syscall entry stop at `clone`, etc (calling pid)
			2. corresponding PTRACE_EVENT_*, delivered via SIGTRAP (calling pid)
			3. a group stop (SIGSTOP) at child pid, which pauses the new child process!
			4. syscall exit stop to finish interrupted syscall (calling pid)

			in a multithreaded  app events form other threads will happen in between them, so it's
			required to track the state of each of the pid to match the events (entry and stops)
		*/
		unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACEVFORK |
		unix.PTRACE_O_TRACECLONE |
		/*
		   Notes on O_TRACEEXIT
		   Upon exit calls ( exit, exit_group, and signal deaths)
		   the tracer will receive SIGTRAP with PTRACE_EVENT_EXIT as its cause
		   then after PtraceSyscall/Wait4 pair the tracer will get wstatus equal to Exited
		   the syscall which started the exit mechanism will not be finished!
		   Generally speaking, using the Exited status should be enough, this is not a debugger, but why not.

		*/
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
	//pid          int
	callNum      uint64
	callName     string
	retVal       uint64
	expectReturn bool
	gotCallNum   bool
	gotRetVal    bool
	//started      bool
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

	appErrChan chan<- error
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

		appErrChan: errorCh,
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

	appName := m.runOpt.Cmd
	appArgs := m.runOpt.Args
	workDir := m.runOpt.WorkDir
	appUser := m.runOpt.User
	runTargetAsUser := m.runOpt.RunAsUser
	rtaSourcePT := m.runOpt.RTASourcePT

	var err error
	var app *exec.Cmd

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
		return nil
	}

	targetPid := app.Process.Pid
	cancelSignalForwarding := startSignalForwarding(m.ctx, app, m.signalCh)
	defer cancelSignalForwarding()

	sysInfo := system.GetSystemInfo()
	archName := system.MachineToArchName(sysInfo.Machine)

	ptReport := &report.PtMonitorReport{
		Enabled:      rtaSourcePT,
		ArchName:     string(archName),
		SyscallStats: map[string]report.SyscallStatInfo{},
	}

	if rtaSourcePT {
		m.runPTrace(targetPid, ptReport)
	} else {
		go func() {
			if err := app.Wait(); err != nil {
				logger.WithError(err).Debug("not tracing target app - state<-AppFailed")
				m.status.err = err
			} else {
				logger.Debug("not tracing target app - state<-AppDone")
			}
			m.status.report = ptReport
		}()
	}
	//NOTE: need a better way to stop the target app...
	if err := app.Process.Signal(unix.SIGTERM); err != nil {
		logger.Warnf("app.Process.Signal(unix.SIGTERM) - error stopping target app => %v", err)
		if err := app.Process.Kill(); err != nil {
			logger.Warnf("app.Process.Kill - error killing target app => %v", *app)
		}
	}

	return nil
}

func (m *monitor) runPTrace(targetPid int, ptReport *report.PtMonitorReport) {

	archName := system.ArchName(ptReport.ArchName)

	syscallResolver := system.CallNumberResolver(archName)

	// Starting the async part...
	go func() {
		logger := log.WithField("op", "sensor.pt.monitor.processor")
		logger.Debug("call")
		defer logger.Debug("exit")

		syscallStats := map[uint32]uint64{}
		eventChan := make(chan syscallEvent, eventBufSize)
		collectorDoneChan := make(chan int, 1)

		go func() {
			logger := log.WithField("op", "sensor.pt.monitor.collector")
			logger.Debug("call")
			defer logger.Debug("exit")

			//IMPORTANT:
			//Ptrace is not pretty... and it requires that you do all ptrace calls from the same thread
			runtime.LockOSThread()

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

			var procState map[int]*ptraceState = make(map[int]*ptraceState)

			procState[targetPid] = &ptraceState{}
		ptrace:
			for {
				var childState *ptraceState
				if state, ok := procState[pid]; !ok {
					procState[pid] = &ptraceState{}
					childState = procState[pid]
				} else {
					childState = state
				}

				var childExited = false
				var childSig = int(0) // not injecting a signal by default.
				switch {
				case wstat.Exited():
					var rc int = 0
					if pid == targetPid {
						if !childState.exiting {
							logger.Warn("app exited (unexpected)")
							rc = 4
						} else {
							rc = 0
						}
						if m.runOpt.ReportOnMainPidExit {
							collectorDoneChan <- rc
							logger.Tracef("[pid %d] main process exited, stopping tracing", targetPid)
							break ptrace
						}
					} else {
						logger.Tracef("[pid %d] - exited, status: %d", pid, wstat.ExitStatus())
						delete(procState, pid)
					}
					childExited = true

				case wstat.Signaled():
					if pid == targetPid {
						logger.Debugf("[pid %d] main process unexpectedly terminated by a signal, stopping tracing", targetPid)
						collectorDoneChan <- 5
						break ptrace
					}
					logger.Warnf("[pid %d]  - signalled (unexpected)", pid)
					childExited = true

				case wstat.Continued():
					logger.Tracef("[pid %d] - continued", pid)

				case wstat.Stopped():

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
							syscall.PTRACE_EVENT_EXEC:

							stopType = "ptrace_event_stop"
							if newPID, err := syscall.PtraceGetEventMsg(targetPid); err != nil {
								logger.Debugf("[pid %d] received '%s' event, failed to get the pid of the new process: %s", pid, ptraceEventEnum(trapCause), err)
							} else {
								procState[int(newPID)] = &ptraceState{}
								logger.Tracef("[pid %d] ptrace stop occurred (%s), event pid = %d, syscall => %s, continue...", pid, ptraceEventEnum(trapCause), newPID, childState.callName)
							}

						case syscall.PTRACE_EVENT_EXIT:
							stopType = "ptrace_event_stop"
							childState.exiting = true
							// setting this to true, to count unfinished syscalls
							// e.g. `exit_group`, which will no longer reach `stopped` state
							// after this event, then next stop after wait4 will SIGTRAP with status exited
							childState.gotRetVal = true
							if logger.Logger.IsLevelEnabled(log.TraceLevel) {
								exitCode, err := syscall.PtraceGetEventMsg(pid)
								if err != nil {
									logger.Tracef("[pid %d] reported exit, failed to get exit code : %s", pid, err)
								} else {
									logger.Tracef("[pid %d] PTRACE_EVENT_EXIT, exit status value: %d", pid, exitCode)
								}
							}

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
						// a signal that likely has to be injected back to the traced process
						// theoretically, signal forwarder will not see this, as it's sent to a process of the tracee
						// whereas signal forwarder sees only the signals delivered to the sensor's main process
						stopType = "signal_stop"
					}

					logger.Tracef(
						"[pid %d] stopSig=> %s, stop type => %v, syscallReturn(%v)",
						pid,
						stopSignalInfo(stopSig),
						stopType,
						childState.expectReturn)

					if stopType != "syscall_stop" {

						if stopType == "signal_stop" {
							childSig = int(stopSig)
							logger.Tracef("[pid %d] injecting signal(%d) with the next PtraceSyscall...", pid, childSig)
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
				default:
					logger.Debugf(
						"[pid %d] wait4 returned unexpected state: %d, stopped, continued, signalled, exited checked",
						pid,
						wstat,
					)
				}

				if childState.gotCallNum && childState.gotRetVal {
					//TODO: need to figure out what to do with unpaired syscalls
					// see above (e.g. ptrace_stops)
					// this should go away(?) if tracking all new process creation calls
					// these should be captured in under their own trap's (SIGTRAP sig) cause
					childState.gotCallNum = false
					childState.gotRetVal = false

					select {
					case eventChan <- syscallEvent{
						pid:     pid,
						callNum: uint32(childState.callNum),
						retVal:  childState.retVal,
					}:
					case <-m.ctx.Done():
						logger.Info("stopping...")
						return
					}
				}

				// continue execution
				if !childExited {
					err = unix.PtraceSyscall(pid, childSig)
					if err != nil {
						// the process could've been killed, which is normal
						if err.(syscall.Errno) != syscall.ESRCH {
							logger.Errorf("[pid %d] trace syscall p sig=%v error - %v (errno=%d)", pid, childSig, err, err.(syscall.Errno))
							m.appErrChan <- errors.SE("ptrace.App.collect.ptsyscall", "call.error", err)
						} else {
							logger.Debugf("[pid %d] PtraceSyscall returned ESRCH ignoring (most likely killed)", pid)
						}
					}
				}

				// wait for any child process to accommodate clones, forks, etc.
				pid, err = unix.Wait4(-1, &wstat, syscall.WALL, nil)
				if err != nil {
					if err.(syscall.Errno) == syscall.ECHILD {
						logger.Debugf("[pid %d] wait4 returned ECHILD error, there nothing more to collect, ...", pid)
						if !procState[targetPid].exiting {
							logger.Debugf("[pid %d] has no children to track and but is not in 'exiting' state", targetPid)
							collectorDoneChan <- 4 // failed main app
							return
						}
						break ptrace
					} else {
						logger.Debugf("unix.Wait4 - error waiting 4 %d: %v", pid, err)
						m.appErrChan <- errors.SE("ptrace.App.collect.wait4", "call.error", err)
						collectorDoneChan <- 2
						return
					}
				}
				if pid != targetPid {
					logger.Tracef("wait4 returned a child pid(%d) of pid(%d)", pid, targetPid)
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

				break done
			case e := <-eventChan:
				ptReport.SyscallCount++
				//logger.Tracef("syscall ==> %d (%s)", e.callNum, syscallResolver(e.callNum))

				syscallStats[e.callNum]++
			}
		}

	drain:
		for {
			select {
			case e := <-eventChan:
				ptReport.SyscallCount++
				logger.Tracef("event (drained) ==> {pid=%v cn=%d}", e.pid, e.callNum)
				syscallStats[e.callNum]++

			default:
				logger.Trace("event draining is finished")
				break drain
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

				var reportSignal = true
				if s == syscall.SIGCHLD && log.IsLevelEnabled(log.TraceLevel) {
					reportSignal = false
				}
				if reportSignal {
					log.WithField("signal", s).Debug("ptmon: signal forwarder - received signal")
				}

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

func ptraceEventEnum(data int) string {
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

func stopSignalInfo(sig syscall.Signal) string {
	sigNum := int(sig)
	if sigNum == -1 {
		return fmt.Sprintf("(code=%d)", sigNum)
	}

	sigEnum := signalEnum(sigNum)
	sigStr := sig.String()
	if sig&traceSysGoodStatusBit == traceSysGoodStatusBit {
		msig := sig &^ traceSysGoodStatusBit
		sigEnum = fmt.Sprintf("%s|0x%04x", signalEnum(int(msig)), traceSysGoodStatusBit)
		sigStr = fmt.Sprintf("%s|0x%04x", msig, traceSysGoodStatusBit)
	}

	info := fmt.Sprintf("(code=%d/0x%04x enum='%s' str='%s')",
		sigNum, sigNum, sigEnum, sigStr)

	return info
}

func sigTrapCauseInfo(cause int) string {
	if cause == -1 {
		return fmt.Sprintf("(code=%d)", cause)
	}

	causeEnum := ptraceEventEnum(cause)
	info := fmt.Sprintf("(code=%d enum=%s)", cause, causeEnum)

	return info
}

func signalEnum(sigNum int) string {
	if sigNum >= len(sigEnums) || sigNum < 0 {
		return fmt.Sprintf("BAD(%d)", sigNum)
	}

	e := sigEnums[sigNum]
	if e == "" {
		e = fmt.Sprintf("UNKNOWN(%d)", sigNum)
	}

	return e
}

var sigEnums = [...]string{
	0:                 "(NOSIGNAL)",
	syscall.SIGABRT:   "SIGABRT/SIGIOT",
	syscall.SIGALRM:   "SIGALRM",
	syscall.SIGBUS:    "SIGBUS",
	syscall.SIGCHLD:   "SIGCHLD",
	syscall.SIGCONT:   "SIGCONT",
	syscall.SIGFPE:    "SIGFPE",
	syscall.SIGHUP:    "SIGHUP",
	syscall.SIGILL:    "SIGILL",
	syscall.SIGINT:    "SIGINT",
	syscall.SIGKILL:   "SIGKILL",
	syscall.SIGPIPE:   "SIGPIPE",
	syscall.SIGPOLL:   "SIGIO/SIGPOLL",
	syscall.SIGPROF:   "SIGPROF",
	syscall.SIGPWR:    "SIGPWR",
	syscall.SIGQUIT:   "SIGQUIT",
	syscall.SIGSEGV:   "SIGSEGV",
	syscall.SIGSTKFLT: "SIGSTKFLT",
	syscall.SIGSTOP:   "SIGSTOP",
	syscall.SIGSYS:    "SIGSYS",
	syscall.SIGTERM:   "SIGTERM",
	syscall.SIGTRAP:   "SIGTRAP",
	syscall.SIGTSTP:   "SIGTSTP",
	syscall.SIGTTIN:   "SIGTTIN",
	syscall.SIGTTOU:   "SIGTTOU",
	syscall.SIGURG:    "SIGURG",
	syscall.SIGUSR1:   "SIGUSR1",
	syscall.SIGUSR2:   "SIGUSR2",
	syscall.SIGVTALRM: "SIGVTALRM",
	syscall.SIGWINCH:  "SIGWINCH",
	syscall.SIGXCPU:   "SIGXCPU",
	syscall.SIGXFSZ:   "SIGXFSZ",
}
