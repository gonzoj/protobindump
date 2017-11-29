#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef unsigned char byte;

typedef enum { TRUE = 1, FALSE = 0 } bool;

typedef unsigned int vaddr;

typedef struct {
	byte *data;
	size_t size;
} buffer_t;

typedef struct {
	buffer_t bin;
	bool *valid;
} pattern_t;

typedef struct {
	buffer_t bin;
	unsigned long base;
} section_t;

const char *s_InternalAddGeneratedFile = "55 8B EC 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 38 A1 ? ? ? ? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 C7 45 C4 00 00 00 00 E8 ? ? ? ?";

section_t text;
section_t rdata;

bool load_sections_from_binary(const char *file) {
	printf("loading sections from binary %s\n", strrchr(file, '/') ? strrchr(file, '/') + 1 : file);

	FILE *f = fopen(file, "rb");
	
	if (!f) return FALSE;

	fseek(f, 0x3c, SEEK_SET);

	// offset to PE signature ("PE\0\0")
	unsigned long signature_offset;
	fread(&signature_offset, sizeof(long), 1, f);

	fseek(f, signature_offset, SEEK_SET);

	char signature[4];
	fread(signature, sizeof(char), 4, f);
	if (strcmp(signature, "PE")) {
		return FALSE;
	}
	
	// seek to optional header
	fseek(f, 20, SEEK_CUR);

	// seek to ImageBase field
	fseek(f, 28, SEEK_CUR);

	// ImageBase field (preferred base address of image when loaded into memory)
	unsigned long image_base;
	fread(&image_base, sizeof(unsigned long), 1, f);

	// seek back to optional header
	fseek(f, signature_offset + 4 + 20, SEEK_SET);

	// seek to first section header
	fseek(f, 224, SEEK_CUR);

	int i = 0;
	while (TRUE) {
		char section[8];
		fread(section, sizeof(char), 8, f);

		if (!strcmp(section, ".text")) {
			printf("extracting section .text\n");

			// seek to VirtualAddress field
			fseek(f, 4, SEEK_CUR);

			unsigned long rva;
			fread(&rva, sizeof(unsigned long), 1, f);
			text.base = image_base + rva;

			unsigned long size;
			fread(&size, sizeof(unsigned long), 1, f);

			unsigned long data;
			fread(&data, sizeof(unsigned long), 1, f);

			text.bin.size = size;
			text.bin.data = malloc(size);

			// seek to section body
			fseek(f, data, SEEK_SET);

			fread(text.bin.data, sizeof(byte), text.bin.size, f);

			// seek to current section header (after name field)
			fseek(f, signature_offset + 4 + 20 + 224 + i * 40 + 8, SEEK_SET);
		} else if (!strcmp(section, ".rdata")) {
			printf("extracting section .rdata\n");

			// seek to VirtualAddress field
			fseek(f, 4, SEEK_CUR);

			unsigned long rva;
			fread(&rva, sizeof(unsigned long), 1, f);
			rdata.base = image_base + rva;

			unsigned long size;
			fread(&size, sizeof(unsigned long), 1, f);

			unsigned long data;
			fread(&data, sizeof(unsigned long), 1, f);

			rdata.bin.size = size;
			rdata.bin.data = malloc(size);

			// seek to section body
			fseek(f, data, SEEK_SET);

			fread(rdata.bin.data, sizeof(byte), rdata.bin.size, f);

			// seek to current section header (after name field)
			fseek(f, signature_offset + 4 + 20 + 224 + i * 40 + 8, SEEK_SET);
		}

		// this is pretty dirty; I'm too lazy to retrieve the actual number of section headers
		if (rdata.bin.size && text.bin.size) break;

		// seek to next sectin header
		fseek(f, 40 - 8, SEEK_CUR);

		i++;
	}

	fclose(f);

	return TRUE;
}

pattern_t get_pattern_from_string(const char *s) {
	pattern_t p = { { NULL, 0 }, NULL };

	char *s_copy = strdup(s);

	char *tok = strtok(s_copy, " ");
	size_t n = 0;

	while (tok) {
		p.bin.data = realloc(p.bin.data, p.bin.size + sizeof(byte));
		p.valid = realloc(p.valid, n * sizeof(bool) + sizeof(bool));

		if (!strcmp(tok, "?")) {
			p.valid[n] = FALSE;
		} else {
			p.valid[n] = TRUE;

			unsigned int b;
			sscanf(tok, "%02X", &b);
			p.bin.data[n] = b & 0xFF;
		}

		p.bin.size = ++n * sizeof(byte);

		tok = strtok(NULL, " ");
	}

	free(s_copy);

	return p;
}

bool compare_buffer_to_pattern(buffer_t *b, int off, pattern_t *p) {
	int i;
	for (i = 0; i < p->bin.size; i++) {
		if (p->valid[i] && p->bin.data[i] != b->data[off + i]) {
			return FALSE;
		}
	}
	
	return TRUE;
}

unsigned long scan_buffer_for_pattern(buffer_t *b, const char *s_p) {
	pattern_t p = get_pattern_from_string(s_p);

	int i;
	for (i = 0; i < b->size; i++) {
		if (compare_buffer_to_pattern(b, i, &p)) {
			return i;
		}
	}

	return 0;
}

// I was too lazy to use a lib for disassembling, so I just let objdump do the job; unfortunately that breaks windows support ;-)
buffer_t generate_assembler_mnemonics(const char *file) {
	printf("generating assembler mnemonics for binary %s\n", strrchr(file, '/') ? strrchr(file, '/') + 1 : file);

	fflush(NULL);

	buffer_t b = { NULL, 0 };

	char cmd[512];
	sprintf(cmd, "objdump -d \"%s\"", file);
	FILE *f = popen(cmd, "r");

	if (!f) return b;

	while (!ferror(f) && !feof(f)) {
		char buf[512];
		size_t n = fread(buf, sizeof(char), 512, f);
		b.data = realloc(b.data, b.size + n);
		memcpy(b.data + b.size, buf, n);
		b.size += n;
	}

	fclose(f);

	return b;
}

// lots of assumptions here... oh well
void retrieve_arguments(char *s_asm, unsigned long *args, int nargs) {
	char *c = s_asm;

	int i;
	for (i = 0; i < nargs; i++, c--) {
		while (*c != '$') c--;
		c++;
		sscanf(c, "0x%x\n", (vaddr *) &args[i]);
		c--;
	}
}

void dump_protobin(unsigned long descriptor, unsigned long size, unsigned long file) {
	printf("dumping %sbin (%u bytes)\n", &rdata.bin.data[file - rdata.base], (unsigned) size);
	
	char protobin[512];
	strcpy(protobin, (char *) &rdata.bin.data[file - rdata.base]);

	char filename[512] = "protobin/";

	mkdir("protobin", S_IRWXU);
	chdir("protobin");

	char *c = protobin;
	char *d = c;
	int i = 1;
	while ((c = strchr(c, '/'))) {
		*c = '\0';

		mkdir(d, S_IRWXU);
		chdir(d);

		i++;
		*c = '/';
		c++;
		d = c;
	}
	while (i--) {
		chdir("..");
	}
	
	strcat(filename, protobin);
	strcat(filename, "bin");

	FILE *f = fopen(filename, "wb");
	
	if (!f) return;

	// dump descriptor to the corresponding file
	fwrite(&rdata.bin.data[descriptor - rdata.base], sizeof(byte), size, f);

	fclose(f);
}

/*
 * Generated protobuf classes call DescriptorPool::InternalAddGeneratedFile and subsequently MessageFactory::InternalRegisterGeneratedFile at init time.
 * We basically check the .text section for calls to InternalAddGeneratedFile, retrieve the arguments (encoded descriptor and its size) as well as the
 * arguments for the next procedure (InternalRegisterGeneratedFile) which is the proto filename and dump the descriptor to its corresponding protobin file.
 */
void parse_assembler_mnemonics(buffer_t *s_asm, unsigned long proc) {
	printf("parsing assembler mnemonics\n");

	char *c = (char *) s_asm->data;
	char call[512];
	sprintf(call, "call   0x%x", (vaddr) proc);

	c = strstr(c, call);
	while (c) {
		// found a call to InternalAddGeneratedFile

		// retrieve arguments
		unsigned long pool_args[2];
		retrieve_arguments(c, (unsigned long *) pool_args, 2);

		c += 4;

		// skip to the next procedure call (InternalRegisterGeneratedFile)
		c = strstr(c, "call");

		// retrieve arguments again
		unsigned long factory_args[1];
		retrieve_arguments(c, (unsigned long *) factory_args, 1);

		// dump the ecncoded descriptor to its corresponding protobin file
		dump_protobin(pool_args[0], pool_args[1], factory_args[0]);

		c += 4;
		c = strstr(c, call);
	}
}

int main(int argc, char **argv) {
	load_sections_from_binary(argv[1]);

	// resolve InternalAddGeneratedfile via pattern matching
	unsigned long rva = scan_buffer_for_pattern(&text.bin, s_InternalAddGeneratedFile);
	printf("DescriptorPool::InternalAddGeneratedFile at 0x%08X\n", (vaddr) (text.base + rva));

	buffer_t s_asm = generate_assembler_mnemonics(argv[1]);

	parse_assembler_mnemonics(&s_asm, text.base + rva);

	exit(EXIT_SUCCESS);
}
