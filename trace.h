#ifndef TRACE_H
#define TRACE_H

#define X86_64

void calltrace(void);
int search_symbol_by_addr(unsigned long addr);
int __search_symbol_by_addr(unsigned long addr);
int load_elf_symbols(char *elf_file);
int init_calltrace(void);
void exit_calltrace(void);

#endif
