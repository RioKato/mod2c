package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	if len(os.Args) <= 1 {
		fmt.Fprintf(os.Stderr, "%s module.ko\n", os.Args[0])
		os.Exit(1)
	}

	err := PrintC(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
}

type ModuleHeader struct {
	ModuleState uint32
	Padding1    uint32
	ListHead    [2]uint64
	Name        [56]byte
}

const ModuleHeaderSize uint64 = 0x50

func PrintC(path string) error {
	file, err := elf.Open(path)
	if err != nil {
		return err
	}

	modinfo := file.Section(".modinfo")
	if modinfo == nil {
		return fmt.Errorf(".modinfo section not found")
	}
	data, err := modinfo.Data()
	if err != nil {
		return err
	}

	var vermagic string
	for _, v := range bytes.Split(data, []byte{0x00}) {

		v := string(v)
		if strings.HasPrefix(v, "vermagic=") {
			vermagic = v[9:]
			break
		}
	}
	if vermagic == "" {
		return fmt.Errorf("vermagic not found")
	}

	relaThisModule := file.Section(".rela.gnu.linkonce.this_module")
	if relaThisModule == nil {
		return fmt.Errorf(".rela.gnu.linkonce.this_module section not found")
	}
	readerRelaThisModule := relaThisModule.Open()
	var initModule elf.Rela64
	err = binary.Read(readerRelaThisModule, binary.LittleEndian, &initModule)
	if err != nil {
		return err
	}

	var exitModule elf.Rela64
	err = binary.Read(readerRelaThisModule, binary.LittleEndian, &exitModule)
	if err != nil {
		return err
	}

	if initModule.Off > exitModule.Off {
		temp := initModule
		initModule = exitModule
		exitModule = temp
	}

	thisModule := file.Section(".gnu.linkonce.this_module")
	if thisModule == nil {
		return fmt.Errorf(".gnu.linkonce.this_module section not found")
	}
	readerThisModule := thisModule.Open()
	var moduleHeader ModuleHeader
	err = binary.Read(readerThisModule, binary.LittleEndian, &moduleHeader)
	if err != nil {
		return err
	}

	if initModule.Off > thisModule.SectionHeader.Size || exitModule.Off > thisModule.SectionHeader.Size {
		return fmt.Errorf(".gnu.linkonce.this_module section invalid address")
	}

	message := `
#ifndef _MODULE_H_
#define _MODULE_H_

__attribute__((section(".modinfo"))) char modinfo[] =
    "name=" MODULE_NAME "\x00vermagic=%s";

__attribute__((section(".gnu.linkonce.this_module"))) struct module {
  char _padding1[24];
  char name[56];
  char _padding2[%d];
  int (*init)(void);
  char _padding3[%d];
  void (*exit)(void);
  char _padding4[%d];
} __attribute__((packed)) __this_module = {
    .name = MODULE_NAME,
    .init = MODULE_INIT,
    .exit = MODULE_EXIT,
};

#endif
`

	fmt.Printf(message, vermagic, initModule.Off-ModuleHeaderSize, exitModule.Off-initModule.Off-0x08, thisModule.SectionHeader.Size-exitModule.Off-0x8)

	return nil
}
