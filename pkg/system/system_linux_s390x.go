package system

import (
	"golang.org/x/sys/unix"
)

/*
S390X SYSCALL REGISTER USE:
source: https://github.molgen.mpg.de/git-mirror/glibc/blob/c0da14cdda1fa552262ce3624156194eef43e973/sysdeps/unix/sysv/linux/s390/s390-64/unix.S#L45

Syscall Number:   r2
Return Value:     r2
1st Param (arg0): r3
2nd Param (arg1): r4
3rd Param (arg2): r5
4th Param (arg3): r6
5th Param (arg4): 320(%r15)?
6th Param (arg5): 328(%r15)?

*/

func LookupCallName(num uint32) string {
	return callNameS390x(num)
}

func LookupCallNumber(name string) (uint32, bool) {
	return callNumberS390x(name)
}

func CallNumber(regs unix.PtraceRegs) uint64 {
	return regs.Orig_gpr2
}

func CallReturnValue(regs unix.PtraceRegs) uint64 {
	return regs.Gprs[2]
}

func CallFirstParam(regs unix.PtraceRegs) uint64 {
	return regs.Gprs[3]
}

func CallSecondParam(regs unix.PtraceRegs) uint64 {
	return regs.Gprs[4]
}

func CallThirdParam(regs unix.PtraceRegs) uint64 {
	return regs.Gprs[5]
}

func CallFourthParam(regs unix.PtraceRegs) uint64 {
	return regs.Gprs[6]
}
