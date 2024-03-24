package system

type ArchName string

const (
	ArchNameUnknown     ArchName = "unknown"
	ArchNameUnsupported ArchName = "unsupported"
	ArchName386         ArchName = "386"
	ArchNameAmd64       ArchName = "amd64"
	ArchNameArm32       ArchName = "armhf"
	ArchNameArm64       ArchName = "aarch64"
	ArchNameS390x       ArchName = "s390x"
)

type MachineName string

const (
	MachineNameNamei386   MachineName = "i386"
	MachineNameNamei586   MachineName = "i586"
	MachineNameNamei686   MachineName = "i686"
	MachineNameNamex86_64 MachineName = "x86_64"
	MachineNameNameArm    MachineName = "armv7l"
	MachineNameNameArm64  MachineName = "aarch64"
	MachineNameNameS390x  MachineName = "s390x"
)

type ArchBits uint8

const (
	ArchBits32 ArchBits = 32
	ArchBits64 ArchBits = 64
)

type ArchFamily string

const (
	ArchFamilyX86   ArchFamily = "x86"
	ArchFamilyArm   ArchFamily = "arm"
	ArchFamilyArm64 ArchFamily = "arm64"
	ArchFamilyS390x ArchFamily = "s390x"
)

type ArchInfo struct {
	Name   ArchName
	Family ArchFamily
	Bits   ArchBits
}

var x86Family64Arch = ArchInfo{
	Name:   ArchNameAmd64,
	Family: ArchFamilyX86,
	Bits:   ArchBits64,
}

var x86Family32Arch = ArchInfo{
	Name:   ArchName386,
	Family: ArchFamilyX86,
	Bits:   ArchBits32,
}

var ArmFamily32Arch = ArchInfo{
	Name:   ArchNameArm32,
	Family: ArchFamilyArm,
	Bits:   ArchBits32,
}

var ArmFamily64Arch = ArchInfo{
	Name:   ArchNameArm64,
	Family: ArchFamilyArm,
	Bits:   ArchBits64,
}

var s390xFamily64Arch = ArchInfo{
	Name:   ArchNameS390x,
	Family: ArchFamilyS390x,
	Bits:   ArchBits64,
}

var unsupportedArch = ArchInfo{
	Name: ArchNameUnsupported,
}

var unknownArch = ArchInfo{
	Name: ArchNameUnknown,
}

var archMap = map[MachineName]*ArchInfo{
	MachineNameNamei386:   &x86Family32Arch,
	MachineNameNamei586:   &x86Family32Arch,
	MachineNameNamei686:   &x86Family32Arch,
	MachineNameNamex86_64: &x86Family64Arch,
	MachineNameNameArm:    &ArmFamily32Arch,
	MachineNameNameArm64:  &ArmFamily64Arch,
	MachineNameNameS390x:  &s390xFamily64Arch,
}

func MachineToArchName(mtype string) ArchName {
	if archInfo, ok := archMap[MachineName(mtype)]; ok {
		return archInfo.Name
	}

	return ArchNameUnknown
}

func MachineToArch(mtype string) *ArchInfo {
	if archInfo, ok := archMap[MachineName(mtype)]; ok {
		return archInfo
	}

	return &unknownArch
}
