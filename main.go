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
		&authenticationInformation,
		uint32(unsafe.Sizeof(authenticationInformation)),
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
	authenticationInformation *win32.KerbInteractiveLogon, // PVOID -- this is a hack for now - we currently only support this one method so explicitly require KerbInteractiveLogon
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

	PrintRawMemoryPointerType(&lsaHandle)
	PrintRawMemoryPointerType(&originName)
	PrintRawMemoryPointerType(originName)
	PrintRawMemoryPointerType(originName.Buffer)
	PrintRawMemoryPointerType(&logonType)
	PrintRawMemoryPointerType(&authenticationPackage)
	PrintRawMemoryPointerType(&authenticationInformation)
	PrintRawMemoryPointerType(authenticationInformation)
	PrintRawMemoryPointerType(&authenticationInformation.LogonDomainName)
	PrintRawMemoryPointerType(authenticationInformation.LogonDomainName.Buffer)
	PrintRawMemoryPointerType(&authenticationInformation.UserName)
	PrintRawMemoryPointerType(authenticationInformation.UserName.Buffer)
	PrintRawMemoryPointerType(&authenticationInformation.Password)
	PrintRawMemoryPointerType(authenticationInformation.Password.Buffer)
	PrintRawMemoryPointerType(&authenticationInformationLength)
	PrintRawMemoryPointerType(&localGroups)
	// PrintRawMemoryPointerType(localGroups)
	PrintRawMemoryPointerType(&sourceContext)
	PrintRawMemoryPointerType(sourceContext)
	PrintRawMemoryPointerType(&profileBuffer)
	PrintRawMemoryPointerType(profileBuffer)
	PrintRawMemoryPointerType(&profileBufferLength)
	PrintRawMemoryPointerType(profileBufferLength)
	PrintRawMemoryPointerType(&logonId)
	PrintRawMemoryPointerType(logonId)
	PrintRawMemoryPointerType(&token)
	PrintRawMemoryPointerType(token)
	PrintRawMemoryPointerType(&quotas)
	PrintRawMemoryPointerType(quotas)
	PrintRawMemoryPointerType(&subStatus)
	PrintRawMemoryPointerType(subStatus)

	return win32.LsaLogonUser(
		lsaHandle,
		originName,
		logonType,
		authenticationPackage,
		authenticationInformation,
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

func PrintRawMemoryPointerType(p interface{}) {
	typ := reflect.Indirect(reflect.ValueOf(p)).Type()
	address := reflect.Indirect(reflect.ValueOf(p)).Addr().Pointer()
	fmt.Printf("%v: %x: %#v\n", typ.Name(), address, p)
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
}
