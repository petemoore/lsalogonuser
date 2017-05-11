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
	for i, c := range []byte("foobarxx") {
		sourceName[i] = c
	}
	for i, c := range sourceName {
		log.Printf("%v: #%v", i, c)
	}

	logonId := win32.LUID{}
	token := syscall.Handle(0)
	quotas := win32.QuotaLimits{}
	subStatus := win32.NtStatus(0)

	profileBufferLength := uint32(0)

	var profileBuffer uintptr

	ts := win32.TokenSource{
		SourceName:       sourceName,
		SourceIdentifier: l,
	}

	PrintRawMemoryPointerType("lsa", &h)
	PrintRawMemoryPointerType("origin", &originName)
	PrintRawMemoryPointerType("*origin.Buffer", originName.Buffer)
	PrintRawMemoryPointerType("packageId", &authPackage)
	PrintRawMemoryPointerType("*authInfo", &authenticationInformation)
	PrintRawMemoryPointerType("source", &ts)
	PrintRawMemoryPointerType("profileBuffer", &profileBuffer)
	PrintRawMemoryPointerType("profileBufferLen", &profileBufferLength)
	PrintRawMemoryPointerType("luid", &logonId)
	PrintRawMemoryPointerType("token", &token)
	PrintRawMemoryPointerType("qlimits", &quotas)
	PrintRawMemoryPointerType("subStatus", &subStatus)

	win32.LsaLogonUser(
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

func PrintRawMemoryPointerType(name string, p interface{}) {
	fmt.Printf("%v: %#v\n", name, p)
	typ := reflect.Indirect(reflect.ValueOf(p)).Type()
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
