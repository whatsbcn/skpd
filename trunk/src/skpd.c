/*
 * http://www.wekk.net/skpd/
 *
 * by Albert Sellares <whats[at]wekk[dot]net> 
 * http://www.wekk.net
 * 2009-04-15
 *
 * This tool lets you dump processes to executable ELF files.
 *
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <elf.h>

#if __x86_64__
#if __linux__
#define ElfX_auxv_t Elf64_auxv_t
#else
#define ElfX_auxv_t Elf64_Auxinfo
#endif
#define ElfX_Dyn Elf64_Dyn
#define ElfX_Ehdr Elf64_Ehdr
#define ElfX_Phdr Elf64_Phdr
#define ElfX_Shdr Elf64_Shdr
#define ElfX_Sym Elf64_Sym
#define uintX_t uint64_t
#endif

#if __i386__ || __MIPSEL__ 
#if __linux__
#define ElfX_auxv_t Elf32_auxv_t
#else
#define ElfX_auxv_t Elf32_Auxinfo
#endif
#define ElfX_Dyn Elf32_Dyn
#define ElfX_Ehdr Elf32_Ehdr
#define ElfX_Phdr Elf32_Phdr
#define ElfX_Shdr Elf32_Shdr
#define ElfX_Sym Elf32_Sym
#define uintX_t uint32_t
#endif

// Represents a memory range used by the program
struct mentry {
    unsigned int top;
    unsigned int base;
};

struct ph {
    unsigned long off;
    unsigned int num;
};

int attached = 0;
int verbose = 0;
int pid = 0;
int ptrsize = 0;

void spam() {
    printf("skpd 1.2 - <whats[@t]wekk.net>\n"
           "==============================\n");
}

void debug(const char * format, ...){
    if (verbose) {
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
}

void usage (char *prg){
    printf ("Process to exec ELF for linux i386, x86_64 and MIPSEL\n"
            "Usage: %s {-p pid | -f file} [-o output_file] [-v]\n", prg);
    fflush(stdout);
    exit(-1);
} 

void attach(){
    int status;
    if (ptrace(PT_ATTACH, pid, 0, 0) == -1){
        printf (" [!] Can't attach pid %d\n", pid); fflush(stdout);
        exit (-1);
    } 
    attached = 1; 
    waitpid(pid, &status, 0);
    printf(" [*] Attached to pid %d.\n", pid); fflush(stdout);
}

void detach(){
    int status;
    if (ptrace(PT_DETACH, pid , (void *)0x01, 0) == -1){
        printf (" [!] can't dettach pid %d\n", pid); fflush(stdout);
        exit (-1);
    } 
    attached = 0; 
    waitpid(pid, &status, 0);
    printf(" [*] Dettached.\n"); fflush(stdout);
}

// Quit function
void quit(char * format, ...){
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    if (attached) detach();
    exit (-1);
}

// Signal handler
static void die(int val) {
    printf(" [!] Received signal %d!\n", val);
    if (attached) detach();
    exit (-1);
}

void mread(unsigned long addr, unsigned int size, unsigned long *dest){
    int c = 0;
    bzero(dest, size);
    errno = 0;
    debug("  => mread addr:0x%lx, size:%ld bytes, dest:%p\n", addr, size, dest);
    for (c = 0; c < size/ptrsize; c++) {
        dest[c] = ptrace(PT_READ_D, pid, (void *)addr+c*ptrsize, 0);
        if(errno != 0) {
            printf("  => 0x%lx ", addr+c); fflush(stdout);
            perror("ptrace");
            errno = 0;
        }
    }
} 

void stackread(unsigned long addr, unsigned int size, unsigned long *dest){
    int c = 0;
    bzero(dest, size);
    errno = 0;
    debug("  => mread addr:0x%lx, size:%ld bytes, dest:%p\n", addr, size, dest);
    for (c = 0; c*ptrsize < size; c++) {
        dest[c] = ptrace(PT_READ_D, pid, (void *)addr+c*ptrsize, 0);
        if(errno != 0) {
            printf("  => 0x%lx ", addr+c); fflush(stdout);
            perror("ptrace");
            errno = 0;
        }
    }
} 

int readmaps(unsigned long *stacktop, unsigned long *stackbase, unsigned long *stacksize, struct mentry **maps) {
    unsigned long addr, endaddr;
    unsigned int lines = 0, i = 0, line = 0;
    char perm[5], buff[256], filename[256];

    sprintf(filename, "/proc/%d/maps", pid);
    FILE *file= fopen(filename, "r");

    // maps in linux
    if (file) {
        printf(" [*] Reading %s ...\n", filename);

        while (fscanf(file, "%[^\n]\n", buff) != EOF) lines++;
        rewind(file);
        *maps = (struct mentry *)malloc(lines*sizeof(struct mentry));
 
        while (fscanf(file, "%lx-%lx %s%[^\n]\n", &addr, &endaddr, perm, buff) != EOF) {
            if (strstr(buff, "[stack]")) {
                fclose(file);
                *stacktop = addr;
                *stackbase = endaddr;
                *stacksize = (endaddr-addr);
                (*maps)[i].top = addr;
                (*maps)[i].base = endaddr;
                debug("  => Stack found on: 0x%lx-0x%lx (%ld bytes)\n", addr, endaddr, *stacksize); 
                return lines;
            } else {
                (*maps)[i].top = addr;
                (*maps)[i].base = endaddr;
                //debug("  => Saved top: %p base: %p\n", (*maps)[i].top, (*maps)[i].base);
                i++;
            } 
        }
    // maps in BSD
    } else {
        sprintf(filename, "/proc/%d/map", pid);
        file= fopen(filename, "r");
        if (!file) return 0;
        
        printf(" [*] Reading %s ...\n", filename);

        while (fscanf(file, "%[^\n]\n", buff) != EOF) lines++;
        rewind(file);
        *maps = (struct mentry *)malloc(lines*sizeof(struct mentry));

        while (fscanf(file, "%lx %lx %s%[^\n]\n", &addr, &endaddr, perm, buff) != EOF) {
            if (line == lines - 1) {
                fclose(file);
                *stacktop = addr;
                *stackbase = endaddr;
                *stacksize = (endaddr-addr);
                (*maps)[i].top = addr;
                (*maps)[i].base = endaddr;
                debug("  => Stack found on: 0x%lx-0x%lx (%ld bytes)\n", addr, endaddr, *stacksize);
                return lines;
            } else {
                (*maps)[i].top = addr;
                (*maps)[i].base = endaddr;
                //debug("  => Saved top: %p base: %p\n", (*maps)[i].top, (*maps)[i].base);
                i++;
            }
            line++;
        }

    }
    fclose(file);
    return 0;
}

// Find auxv on stack
int find_auxv(unsigned long *stack, unsigned int size,  struct ph **vauxv){
    char *ptr = (char *)stack;
    unsigned int i = 0;
    *vauxv = malloc(sizeof(struct ph)*4);
    bzero(*vauxv, sizeof(struct ph)*4);

    ElfX_auxv_t *auxv;
    ElfX_auxv_t *auxv2 = 0;
    auxv = (ElfX_auxv_t *)ptr;
    while (ptr < (char *)stack+size-sizeof(ElfX_auxv_t)) {
        while (auxv->a_type != 6 && auxv->a_un.a_val != 1000 && ptr < (char*)stack+size-sizeof(ElfX_auxv_t)) {
            ptr++;
            auxv = (ElfX_auxv_t *)ptr;
            auxv2 = auxv;
        }
        for (auxv++; auxv < (ElfX_auxv_t *)((char*)stack+size-sizeof(ElfX_auxv_t)) && auxv->a_un.a_val != AT_NULL; auxv++) {
            if ( auxv->a_type == AT_PHDR) {
                debug("  => AT_PHDR is: 0x%x\n" ,auxv->a_un.a_val);
                (*vauxv)[3].off = (*vauxv)[2].off;
                (*vauxv)[2].off = (*vauxv)[1].off;
                (*vauxv)[1].off = (*vauxv)[0].off;
                (*vauxv)[0].off = auxv->a_un.a_val;
            } else if ( auxv->a_type == AT_PHNUM) {
                debug("  => AT_PHNUM is: 0x%x\n" ,auxv->a_un.a_val);
                (*vauxv)[3].num = (*vauxv)[2].num;
                (*vauxv)[2].num = (*vauxv)[1].num;
                (*vauxv)[1].num = (*vauxv)[0].num;
                (*vauxv)[0].num = auxv->a_un.a_val;
                i++;
            }
        }
        
        for (auxv2--; auxv2 < (ElfX_auxv_t *)((char*)stack+size-sizeof(ElfX_auxv_t)) && auxv2->a_un.a_val != AT_NULL; auxv2--) {
            if ( auxv2->a_type == AT_PHNUM) {
                debug("  => AT_PHNUM is: 0x%x\n" ,auxv2->a_un.a_val);
                (*vauxv)[3].num = (*vauxv)[2].num;
                (*vauxv)[2].num = (*vauxv)[1].num;
                (*vauxv)[1].num = (*vauxv)[0].num;
                (*vauxv)[0].num = auxv2->a_un.a_val;
            } else if ( auxv2->a_type == AT_PHDR) {
                debug("  => AT_PHDR is: 0x%x\n" ,auxv2->a_un.a_val);
                (*vauxv)[3].off = (*vauxv)[2].off;
                (*vauxv)[2].off = (*vauxv)[1].off;
                (*vauxv)[1].off = (*vauxv)[0].off;
                (*vauxv)[0].off = auxv2->a_un.a_val;
                i++;
            }
        }
        ptr++;
    }
    
    return i;
}

int check_range(struct ph *vauxv, unsigned int iauxv, struct mentry *maps, unsigned int nmaps) {
    int i;
    for (i = 0; i < nmaps; i++) {
        if (vauxv[iauxv].off <= maps[i].base && vauxv[iauxv].off >= maps[i].top) {
            return 1;
        }
    }
    debug("  => %x out of range\n", vauxv[iauxv].off);
    return 0;
}

int main(int argc, char *argv[]) {
    int opt, devnullfd;
    unsigned long stacktop, stackbase, stacksize, nmaps, nauxv;
    unsigned int i, j, filesize = 0, dynamic = 0, base_addr = 0, data_addr = 0;
    unsigned long *buff;    
    struct ph *vauxv;
    struct mentry *maps;
    char *newelf = 0, *outfile = 0, *execfile = 0;
    FILE *fp;
    ptrsize = sizeof(int *);

    ElfX_Ehdr *ehdr;
    ElfX_Phdr *phdr;
    ElfX_Dyn  *dyn;
    spam();

#if __x86_64__ || __i386__                
    uintX_t adata;
    int plt_off;
    int f = 0;                
#endif

    if (argc < 2) usage(argv[0]);

    while ((opt = getopt (argc, argv, "vhp:o:f:")) != -1) {
        switch (opt){
            case 'h': usage(argv[0]); break;
            case 'v': verbose = 1; break;
            case 'p': pid = strtol(optarg, 0,  10); break;
            case 'o': outfile = optarg; break;
            case '?': quit (" [!] Uknown argument.", -1); break;
            case 'f': execfile = optarg; break;
            default : usage(argv[0]); break;
        } 
    }

    if (execfile) {
        printf(" [*] Launching %s > /dev/null.\n", execfile);
        pid = fork();
        if (pid == 0) {
            devnullfd = open("/dev/null", O_RDWR);
            dup2(devnullfd, 1);
            execl(execfile, execfile, (const char *) NULL);
			
        }    
		sleep(1);
    }
    
    if (!pid) quit(" [!] Uknown pid or file.\n");

    signal(SIGILL, die);
    signal(SIGBUS, die);
    signal(SIGFPE, die);
    signal(SIGINT, die);
    signal(SIGTERM, die);
    signal(SIGSEGV, die);

    // attach to process
    attach();

    // read process maps through /proc
    if (!(nmaps = readmaps(&stacktop, &stackbase, &stacksize, &maps))) quit(" [!] Stack not found.\n");
    else debug(" [*] Found %ld maps.\n", nmaps);

    // dump stack
    buff = malloc(stacksize);
    if (!buff) quit(" [!] Malloc error.\n");
    stackread(stacktop, stacksize, buff);

    // found PHDR in stack
	if (!(nauxv = find_auxv(buff, stacksize, &vauxv))) quit(" [!] Auxiliar vector not found.\n");
    debug(" [*] Found %ld possible auxv.\n", nauxv);

    // check that it is a valid PHDR
    for (i = 0; i < nauxv && !check_range(vauxv, i, maps, nmaps); i++);
    if (i == nauxv) quit(" [!] All the auxv are out of range.\n");
    debug(" [*] Auxv selected: off:0x%lx num:0x%x\n", vauxv[i].off, vauxv[i].num);
   
    // use the PHDR to found PT_LOAD sections 
    buff = realloc(buff, vauxv[i].num*sizeof(ElfX_Phdr));
    mread(vauxv[i].off, vauxv[i].num*sizeof(ElfX_Phdr), (unsigned long *)buff);
    phdr = (ElfX_Phdr *)buff;

    for (j = 0; j < vauxv[i].num; j++){
        switch(phdr[j].p_type){
            case PT_LOAD:
                // dump all the binary
                debug("  => Found section %d type PT_LOAD\n", j);
                if (filesize < phdr[j].p_offset + phdr[j].p_filesz){
                    filesize = phdr[j].p_offset + phdr[j].p_filesz;
                    newelf = realloc(newelf, filesize);
                } 
                mread(phdr[j].p_vaddr, phdr[j].p_filesz, (unsigned long *)(phdr[j].p_offset + newelf));
                break;
            case PT_DYNAMIC:
                // it is a dynamic executable
                dynamic = j;
                debug("  => Found section %d type PT_DYNAMIC\n", j);
                break;
            default:
                debug("  => Found section %d type %d\n", j, phdr[j].p_type);
        }
    } 

    // remove sections from ELF headers
    printf(" [*] Rebuilding ELF headers.\n");
    ehdr = (ElfX_Ehdr *)newelf;
    ehdr->e_shoff = 0;
    ehdr->e_shstrndx = 0;
    ehdr->e_shnum = 0;

    // start working with the new ELF
    phdr = (ElfX_Phdr *)(newelf + ehdr->e_phoff);

    // 
    for (j = 0; j < ehdr->e_phnum; j++){
        switch(phdr[j].p_type){
            case PT_LOAD:
                if (phdr[j].p_vaddr <= ehdr->e_entry){
                    // the PT_LOAD section with entry point, is the .text 
                    debug("  => Found .text section.\n");
                    base_addr = phdr[j].p_vaddr;
                }else{
                    // the others are .data
                    debug("  => Found .data section.\n");
                    data_addr = phdr[j].p_vaddr - phdr[j].p_offset;
                }
                break;
        }
    }

    // rebuild dynamic links
    if (dynamic) {
        dyn = (ElfX_Dyn *)(newelf + phdr[dynamic].p_offset); 
        j=0;
        while (dyn[j].d_tag != DT_NULL){
            switch (dyn[j].d_tag){
                case DT_PLTGOT:
#if __x86_64__ || __i386__                
					debug("  => Fixing .got.plt section.\n");
					// Clean the two addr on .got.plt, that are at offset + one addr
                    memset(&newelf[dyn[j].d_un.d_ptr - data_addr + ptrsize], 0, ptrsize*2);

                    f = ptrsize*3;
                    memcpy (&adata, &newelf[dyn[j].d_un.d_ptr-data_addr+f], sizeof(adata));

                    // go forward looking for plt section
                    while (adata != 0) {
						if (adata  < phdr[dynamic].p_vaddr+filesize){
                            adata = adata - 0x10*((f/ptrsize)-3);
                            goto plt;
                        }
                        // look in the next addr
                        f += ptrsize;
                        memcpy(&adata, &newelf[dyn[j].d_un.d_ptr - data_addr + f], sizeof(adata));
                        if ((f>1200)) {
                            printf (" [!] .rel.plt not found.\n");
                            goto end;
                        }
                   }
                plt:
                    // found plt offset
                    plt_off = adata;
                    f = ptrsize*3;
                    memcpy (&adata, &newelf[dyn[j].d_un.d_ptr - data_addr + f], sizeof(adata));
                    while (adata != 0) {
                        // if it was resolved, put the correct value
                        if (adata != plt_off+0x10*((f/ptrsize)-3)){
                            adata = plt_off+0x10*((f/ptrsize)-3);
                            memcpy(&newelf[dyn[j].d_un.d_ptr-data_addr+f], &adata, sizeof(adata));
                        }
                        f += ptrsize;
                        memcpy (&adata, &newelf[dyn[j].d_un.d_ptr-data_addr+f], sizeof(adata));
                    }
                    break;
#endif
#if __MIPSEL__
					debug("  => I can't fix .got section on MIPS, hacking it.\n");
					debug(" [!] This file can be only executed in this system.\n");
                    memcpy(&newelf[dyn[j].d_un.d_ptr - data_addr + ptrsize*2], &base_addr, ptrsize);
                    goto end;
#endif
                } 
                j++;
            }
        }
    end:

    // write the new ELF into a file
    if (outfile){
        if (( fp = fopen(outfile,"w+")) == NULL ) quit(" [!] Can't create file %s.\n", outfile);
        if (fwrite(newelf, 1, filesize, fp) != filesize) quit(" [!] Error writing file.\n");
        fclose (fp);
        chmod(outfile, 00755);
        printf(" [*] File %s saved!\n", outfile);
    } 

    // if -f was used, kill the program
    if (execfile) {
        printf(" [*] Killing %s\n", execfile);
        kill(pid, 15);
    }

    free(maps);
    free(buff);
    free(newelf);
    quit (" [*] Done!\n");
    return 0;
}


