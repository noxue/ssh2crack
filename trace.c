/*
 * trace.c (c) 2012 wzt		http://www.cloud-sec.org
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "trace.h"

#define X86_64

#ifdef X86_32
#define GET_BP(x)      asm("movl %%ebp, %0":"=r"(x))
static Elf32_Ehdr *elf_ehdr;
static Elf32_Phdr *elf_phdr;
static Elf32_Shdr *elf_shdr;
static Elf32_Shdr *shstrtab;
static Elf32_Sym *symtab_ptr;
#else
#define GET_BP(x)      asm("movq %%rbp, %0":"=r"(x))
static Elf64_Ehdr *elf_ehdr;
static Elf64_Phdr *elf_phdr;
static Elf64_Shdr *elf_shdr;
static Elf64_Shdr *shstrtab;
static Elf64_Sym *symtab_ptr;
#endif

static unsigned long *top_rbp;
static char *real_strtab;
static char *strtab_ptr;
static int elf_fd;
static struct stat elf_stat;
static char *strtab_buffer;
static int symtab_num;

void signal_handler(int sig_num, siginfo_t *sig_info, void *ptr)
{
	assert(sig_info != NULL);

	calltrace();
	exit(-1);
}

void calltrace(void)
{
	unsigned long *rbp;
	unsigned long rip = 0;
	unsigned long func_ip = 0;
	char *symbol_name;

	printf("Call trace:\n\n");
	GET_BP(rbp);
	while (rbp != top_rbp) {
		//printf("rbp = 0x%x\n", rbp);
		rip = *(unsigned long *)(rbp + 1);
		//printf("eip = 0x%x\n", rip);
		rbp = (unsigned long *)*rbp;
		if (search_symbol_by_addr(rip) == -1)
			return ;
	}
	printf("\n");
}

int check_elf_header(Elf64_Ehdr *ehdr)
{
	if (ehdr->e_ident[EI_MAG0] != 0x7f
		|| ehdr->e_ident[EI_MAG1] != 'E'
		|| ehdr->e_ident[EI_MAG1] != 'L'
		|| ehdr->e_ident[EI_MAG1] != 'F') {
		return -1;
	}

	return 0;
}

void show_calltrace(char *symbol_name, unsigned long symbol_addr, 
		unsigned int size, unsigned long rip)
{
	char buff[1024];

	snprintf(buff, sizeof(buff), "[<0x%x>] %s + 0x%x/0x%x\n", 
			rip, symbol_name, rip - symbol_addr, size);
	printf("%s", buff);
}

char *search_symbol_by_addr(unsigned long addr)
{
	int i;

	for (i = 0; i < symtab_num; i++) {
		if (symtab_ptr[i].st_value < addr &&
			symtab_ptr[i].st_value + symtab_ptr[i].st_size > addr) {
			show_calltrace(strtab_buffer + symtab_ptr[i].st_name,
					symtab_ptr[i].st_value,
					symtab_ptr[i].st_size,
					addr);
			return ;
		}
	}
	//printf("not found.\n");

	return NULL;
}

void print_symtab(void)
{
	int i;

        for (i = 0; i < symtab_num; i++) {
                fprintf(stdout,"%4d     %25s    0x%08x  x%08x   0x%02x  %4d\n", i,
                        strtab_buffer + symtab_ptr[i].st_name,
                        symtab_ptr[i].st_value,
                        symtab_ptr[i].st_size,
                        symtab_ptr[i].st_info,
                        symtab_ptr[i].st_shndx);
        }
}

int load_elf_symbols(char *elf_file)
{
	unsigned int strtab_off, strtab_size;
	int phdr_len, shdr_len;
	int shstrtab_off, shstrtab_len;
	int symtab_off, symtab_size, i;
	char *buffer;

	assert(elf_file != NULL);
	elf_fd = open(elf_file, O_RDONLY);
	if (elf_fd == -1) {
		perror("open");
		goto out;
	}

	if (fstat(elf_fd, &elf_stat) == -1) {
		perror("fstat");
		goto out;
	}

	elf_ehdr = mmap(0, elf_stat.st_size, PROT_READ, MAP_SHARED, elf_fd, 0);
	if (elf_ehdr == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

/*
	if (check_elf_header(elf_ehdr) == -1) {
		printf("check elf failed.\n");
		goto out_mmap;
	}
*/

#ifdef X86_32
	elf_phdr = (Elf32_Phdr *)((unsigned long)elf_ehdr + elf_ehdr->e_phoff);
	elf_shdr = (Elf32_Shdr *)((unsigned long)elf_ehdr + elf_ehdr->e_shoff);
#else
	elf_phdr = (Elf64_Phdr *)((unsigned long)elf_ehdr + elf_ehdr->e_phoff);
	elf_shdr = (Elf64_Shdr *)((unsigned long)elf_ehdr + elf_ehdr->e_shoff);
#endif

	shstrtab = &elf_shdr[elf_ehdr->e_shstrndx];
	shstrtab_off = (unsigned int)shstrtab->sh_offset;
	shstrtab_len = shstrtab->sh_size;
	real_strtab = (char *)((unsigned long)elf_ehdr + shstrtab_off );

	buffer = malloc(shstrtab_len + 1);
	if (!buffer) {
		printf("Malloc faled.\n");
		goto out;
	}

	memcpy(buffer, real_strtab, shstrtab_len + 1);
	shdr_len = elf_ehdr->e_shoff;

	for (i = 0 ; i < (int)elf_ehdr->e_shnum ; i++){
		if (!strcmp(buffer + elf_shdr[i].sh_name,".symtab")) {
			symtab_off = (unsigned int)elf_shdr[i].sh_offset;
			symtab_size = (unsigned int)elf_shdr[i].sh_size;
			symtab_num = (int )(elf_shdr[i].sh_size / elf_shdr[i].sh_entsize);
			//printf("[+] .symtab off : 0x%x num :%d\n", symtab_off, symtab_num);
                }

                if (!strcmp(buffer + elf_shdr[i].sh_name,".strtab")) {
			strtab_off = (unsigned int)elf_shdr[i].sh_offset;
			strtab_size = (unsigned int)elf_shdr[i].sh_size;
			//printf("[+] .strtab off : 0x%x num : %d\n", strtab_off, strtab_size);
		}
        }
	free(buffer);

	strtab_ptr = (char *)((unsigned long)elf_ehdr + strtab_off);
	strtab_buffer = malloc(strtab_size + 1);
	if (!strtab_buffer) {
		printf("Malloc failed.\n");
		goto out;
	}

	memcpy(strtab_buffer, strtab_ptr, strtab_size + 1);

	symtab_ptr = malloc(symtab_size + 1);
	if (!symtab_ptr) {
		printf("Malloc failed.\n");
		free(strtab_ptr);
		goto out;
	}
	memcpy(symtab_ptr, (char *)((unsigned long)elf_ehdr + symtab_off), symtab_size + 1);

	return 0;

out_mmap:
	munmap(elf_ehdr, elf_stat.st_size);
out:
	close(elf_fd);
	return -1;
}

void free_elf_mmap(void)
{
	munmap(elf_ehdr, elf_stat.st_size);
	close(elf_fd);
}

int get_self_path(char *proc_path, int proc_path_len)
{
	char path[1024];
	int size;

	snprintf(path, sizeof(path), "/proc/%d/exe", getpid());
	printf("%s\n", path);
	size = readlink(path, proc_path, proc_path_len);
	if (size == -1) {
		perror("readlink");
		return -1;
	}
	proc_path[size] = '\0';

	return 0;
}

int init_signal(void)
{
	struct sigaction sa;

	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = signal_handler;

	if (sigaction(SIGSEGV, &sa, NULL) == -1) {
		perror("sigaction");
		return -1;
	}

	return 0;
}

int init_calltrace(void)
{
	char self_path[1024];

	GET_BP(top_rbp);
	printf("top_rbp = 0x%x\n\n", top_rbp);

	if (init_signal() == -1)
		return -1;

	get_self_path(self_path, sizeof(self_path));
	if (!self_path)
		return -1;
	printf("%s\n", self_path);

	if (load_elf_symbols(self_path) == -1)
		return -1;

	/* We just want to use the strtab_ptr & symtab_str that has allocated 
	   above, so we can munmap the file now.*/ 
	free_elf_mmap();

	return 0; 
}

void exit_calltrace(void)
{
	free(strtab_buffer);
	free(symtab_ptr);
}
