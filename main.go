package main

import (
	"fmt"
	"log"
	"reflect"
	"strings"
	"syscall"
	"unsafe"

	"github.com/taskcluster/ntr"
	"github.com/taskcluster/runlib/win32"
)

func main() {
	h := syscall.Handle(0)
	err := win32.LsaConnectUntrusted(&h)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Handle: %v", h)
	authPackage := uint32(0)
	err = win32.LsaLookupAuthenticationPackage(h, &win32.MICROSOFT_KERBEROS_NAME_A, &authPackage)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Auth package: %v", authPackage)

	l := win32.LUID{}
	err = win32.AllocateLocallyUniqueId(&l)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("LUID: %#v", l)

	authenticationInformation := win32.KerbInteractiveLogon{
		MessageType:     2, // KerbInteractiveLogon
		LogonDomainName: ntr.LSAUnicodeStringMustCompile(""),
		UserName:        ntr.LSAUnicodeStringMustCompile("someuser"),
		Password:        ntr.LSAUnicodeStringMustCompile("qwertQWERT123"),
	}

	PrintRawMemoryPointerType("ORIGINAL authenticationInformation", &authenticationInformation)

	domainNameCopy := (*(*[1<<31 - 1]byte)(unsafe.Pointer(authenticationInformation.LogonDomainName.Buffer)))[:authenticationInformation.LogonDomainName.MaximumLength]
	userNameCopy := (*(*[1<<31 - 1]byte)(unsafe.Pointer(authenticationInformation.UserName.Buffer)))[:authenticationInformation.UserName.MaximumLength]
	passwordCopy := (*(*[1<<31 - 1]byte)(unsafe.Pointer(authenticationInformation.Password.Buffer)))[:authenticationInformation.Password.MaximumLength]

	// PrintRawMemoryPointerType("domainNameCopy", &domainNameCopy[0])
	PrintRawMemoryPointerType("userNameCopy", &userNameCopy[0])
	PrintRawMemoryPointerType("passwordCopy", &passwordCopy[0])

	authenticationInformationLength := uint32(unsafe.Sizeof(win32.KerbInteractiveLogon{})) + uint32(authenticationInformation.LogonDomainName.MaximumLength+authenticationInformation.UserName.MaximumLength+authenticationInformation.Password.MaximumLength)

	authInfoBuffer := make([]byte, authenticationInformationLength)

	PrintRawMemoryPointerType("EMPTY authInfoBuffer", &authInfoBuffer[0])

	authenticationInformation.LogonDomainName.Buffer = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(&authInfoBuffer[0])) + unsafe.Sizeof(win32.KerbInteractiveLogon{})))
	authenticationInformation.UserName.Buffer = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(authenticationInformation.LogonDomainName.Buffer)) + uintptr(authenticationInformation.LogonDomainName.MaximumLength)))
	authenticationInformation.Password.Buffer = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(authenticationInformation.UserName.Buffer)) + uintptr(authenticationInformation.UserName.MaximumLength)))

	PrintRawMemoryPointerType("UPDATED authenticationInformation", &authenticationInformation)

	authInfoCopy := (*(*[1<<31 - 1]byte)(unsafe.Pointer(&authenticationInformation)))[:unsafe.Sizeof(authenticationInformation)]

	PrintRawMemoryPointerType("authInfoCopy", &authInfoCopy[0])
	authInfoCopy = append(authInfoCopy, domainNameCopy...)
	PrintRawMemoryPointerType("authInfoCopy with domainName added", &authInfoCopy[0])
	authInfoCopy = append(authInfoCopy, userNameCopy...)
	PrintRawMemoryPointerType("authInfoCopy with UserName added", &authInfoCopy[0])
	authInfoCopy = append(authInfoCopy, passwordCopy...)
	PrintRawMemoryPointerType("authInfoCopy with password added", &authInfoCopy[0])
	copy(authInfoBuffer, authInfoCopy)

	PrintRawMemoryPointerType("authInfoBuffer with copied from authInfoCopy", &authInfoBuffer[0])

	ai := (*win32.KerbInteractiveLogon)(unsafe.Pointer(&authInfoBuffer[0]))

	PrintRawMemoryPointerType("FINAL authenticationInformation", ai)

	originName := win32.LSAStringMustCompile("TestAppFoo")

	sourceName := [8]byte{}
	for i, c := range []byte("foobar") {
		sourceName[i] = c
	}
	for i, c := range sourceName {
		log.Printf("%v: #%v", i, c)
	}

	logonId := win32.LUID{}
	token := syscall.Handle(0)
	quotas := win32.QuotaLimits{}
	subStatus := win32.NtStatus(0)
	// lg := win32.TokenGroups{}

	profileBufferLength := uint32(0)

	var profileBuffer uintptr

	ts := win32.TokenSource{
		SourceName:       sourceName,
		SourceIdentifier: l,
	}

	LsaLogonUser(
		h,
		&originName,
		2, // Interactive
		authPackage,
		ai,
		authenticationInformationLength,
		nil,
		&ts,
		&profileBuffer,
		&profileBufferLength,
		&logonId,
		&token,
		&quotas,
		&subStatus,
	)
}

func LsaLogonUser(
	lsaHandle syscall.Handle, // HANDLE
	originName *win32.LSAString, // PLSA_STRING
	logonType win32.SecurityLogonType, // SECURITY_LOGON_TYPE
	authenticationPackage uint32, // ULONG
	authenticationInformation *win32.KerbInteractiveLogon, // PVOID
	authenticationInformationLength uint32, // ULONG
	localGroups *win32.TokenGroups, // PTOKEN_GROUPS
	sourceContext *win32.TokenSource, // PTOKEN_SOURCE
	profileBuffer *uintptr, // PVOID*
	profileBufferLength *uint32, // PULONG
	logonId *win32.LUID, // PLUID
	token *syscall.Handle, // PHANDLE
	quotas *win32.QuotaLimits, // PQUOTA_LIMITS
	subStatus *win32.NtStatus, // PNTSTATUS
) (err error) {

	PrintRawMemoryPointerType("&lsaHandle", &lsaHandle)
	PrintRawMemoryPointerType("&originName", &originName)
	PrintRawMemoryPointerType("originName", originName)
	PrintRawMemoryPointerType("originName.Buffer", originName.Buffer)
	PrintRawMemoryPointerType("&logonType", &logonType)
	PrintRawMemoryPointerType("&authenticationPackage", &authenticationPackage)
	PrintRawMemoryPointerType("&authenticationInformation", &authenticationInformation)
	PrintRawMemoryPointerType("authenticationInformation", authenticationInformation)
	PrintRawMemoryPointerType("authenticationInformation.LogonDomainName.Buffer", authenticationInformation.LogonDomainName.Buffer)
	PrintRawMemoryPointerType("authenticationInformation.UserName.Buffer", authenticationInformation.UserName.Buffer)
	PrintRawMemoryPointerType("authenticationInformation.Password.Buffer", authenticationInformation.Password.Buffer)
	PrintRawMemoryPointerType("&authenticationInformationLength", &authenticationInformationLength)
	PrintRawMemoryPointerType("&localGroups", &localGroups)
	// PrintRawMemoryPointerType(localGroups)
	PrintRawMemoryPointerType("&sourceContext", &sourceContext)
	PrintRawMemoryPointerType("sourceContext", sourceContext)
	PrintRawMemoryPointerType("&profileBuffer", &profileBuffer)
	PrintRawMemoryPointerType("profileBuffer", profileBuffer)
	PrintRawMemoryPointerType("&profileBufferLength", &profileBufferLength)
	PrintRawMemoryPointerType("profileBufferLength", profileBufferLength)
	PrintRawMemoryPointerType("&logonId", &logonId)
	PrintRawMemoryPointerType("logonId", logonId)
	PrintRawMemoryPointerType("&token", &token)
	PrintRawMemoryPointerType("token", token)
	PrintRawMemoryPointerType("&quotas", &quotas)
	PrintRawMemoryPointerType("quotas", quotas)
	PrintRawMemoryPointerType("&subStatus", &subStatus)
	PrintRawMemoryPointerType("subStatus", subStatus)

	ai := (*byte)(unsafe.Pointer(&authenticationInformation))

	return win32.LsaLogonUser(
		lsaHandle,
		originName,
		logonType,
		authenticationPackage,
		ai,
		authenticationInformationLength,
		localGroups,
		sourceContext,
		profileBuffer,
		profileBufferLength,
		logonId,
		token,
		quotas,
		subStatus,
	)
}

func PrintRawMemoryPointerType(name string, p interface{}) {
	typ := reflect.Indirect(reflect.ValueOf(p)).Type()
	address := reflect.Indirect(reflect.ValueOf(p)).Addr().Pointer()
	fmt.Printf("%v:\n", name)
	fmt.Printf("%x:\n", address)
	buf := ""
	x := 0
	for ; x < int(typ.Size()); x++ {
		e := *(*uint8)(unsafe.Pointer((uintptr(unsafe.Pointer(reflect.ValueOf(p).Pointer())) + uintptr(x))))
		if x%16 == 0 {
			if x > 0 {
				fmt.Printf("  %v\n", buf)
				buf = ""
			}
			fmt.Printf("  %04x ", x)
		}
		fmt.Printf(" %02x", e)
		if e >= 0x20 && e <= 0x7e {
			buf = buf + string([]byte{e})
		} else {
			buf = buf + "."
		}
	}
	// last line might have < 16 entries
	if x%16 > 0 {
		fmt.Print(strings.Repeat(" ", 3*(16-x%16)))
	}
	fmt.Printf("  %v\n", buf)
	// fmt.Printf("\n%#v\n", p)
}
