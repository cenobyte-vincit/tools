/* cgrep-elf64.c - 2018 elf64 update of eSDee's elf32 cgrep.c
 *
 * $ ./cgrep core.10143 cenobyte
 * Match at: 0x56374b96db5c
 * Match at: 0x56374b96dbb2
 * Match at: 0x56374b96eb50
 * Match at: 0x56374b96f3a6
 * Match at: 0x56374b97ece0
 * Match at: 0x56374b97ed00
 *
 */
/* coregrep - by eSDee of Netric (www.netric.org)
   ----------------------------------------------

   Usage:
   $ ./cgrep core "floppppp"
   Match at: 0xBADe5Dee
*/

#include <sys/stat.h>

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
	struct stat fstat_struct;

	char *filedata;

	int iRead  = 0;
	int i      = 0;
	int k      = 0;

	Elf64_Ehdr *elf_header;
	Elf64_Phdr *program_header;

	if (argc < 3) {
		fprintf(stderr, "%s <coredump> <string>\n", argv[0]);
		return -1;
	}

	if ((iRead = open(argv[1], O_RDONLY)) < 0) {
		fprintf(stderr, "Unable to open %s!\n", argv[1]);
		return -1;
	}

        if ((fstat(iRead, &fstat_struct)) < 0) {
		fprintf(stderr, "fstat failed!\n");
                close(iRead);
		return -1;
        }

        if (!(filedata=(char *)malloc(fstat_struct.st_size))) {
		fprintf(stderr, "malloc failed!\n");
                close(iRead);
		return -1;
	}

	memset(filedata, 0x0, fstat_struct.st_size);

	if (read(iRead, filedata, fstat_struct.st_size) < 0) {
		fprintf(stderr, "read failed!\n");
		free(filedata);
		close(iRead);
		return -1;
	}

	elf_header = (Elf64_Ehdr *)filedata;

	if (!(elf_header->e_type  == ET_CORE && elf_header->e_machine == EM_X86_64)) {
		fprintf(stderr, "Not an EM_X86_64 coredump!\n\n");
		free(filedata);
                close(iRead);
		return -1;
	}

	for (i=0; i < elf_header->e_phnum; i++) {
		program_header  = (Elf64_Phdr *)(filedata + elf_header->e_phoff + (i * elf_header->e_phentsize));
		for (k = program_header->p_offset; k < program_header->p_offset + program_header->p_filesz; k++)
			if (!strncmp((filedata + k), argv[2], strlen(argv[2])))
				fprintf(stdout, "Match at: 0x%08lx\n", (program_header->p_vaddr + k - program_header->p_offset));

	}

	free(filedata);
	close(iRead);
	return 0;
}
