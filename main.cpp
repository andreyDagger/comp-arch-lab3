#include <iostream>
#include <algorithm>
#include <map>
#include <string>

uint32_t file_length;

const uint32_t MAX_SIZE = 1e5;
const uint32_t MAX_STRTAB_COUNT = 1e4;
uint8_t* buf;
uint32_t strtab_offset[MAX_STRTAB_COUNT];
uint32_t main_address = 0;

const uint8_t RISCV_ID = 0xf3;
const uint8_t SYMTAB_ID = 0x02;
const uint8_t STRTAB_ID = 0x03;
const uint8_t PROGBITS_ID = 0x01;

const uint32_t E_OFFSET_BIT_DEPTH = 0x04;
const uint32_t E_OFFSET_ENDIANNESS = 0x05;
const uint32_t E_OFFSET_ISA = 0x12;
const uint32_t E_OFFSET_SECTION_HEADER = 0x20;
const uint32_t E_OFFSET_SECTION_HEADER_TABLE_INDEX = 0x32;
const uint32_t E_OFFSET_ESHNUM = 0x30;
const uint32_t SH_OFFSET_TYPE = 0x04;
const uint32_t SH_OFFSET_OFFSET = 0x10;
const uint32_t SH_OFFSET_SIZE = 0x14;

const uint32_t ELF32_SHDR_SIZE = sizeof(int32_t) * 10; // 10 - количество полей в одном элементе массива
const uint32_t SYMTAB_SIZE = 4 * 3 + 2 + 1 + 1;

std::map<uint8_t, std::string> id_to_type = {{0, "NOTYPE"}, {1, "OBJECT"}, {2, "FUNC"},
 {3, "SECTION"}, {4, "FILE"}, {5, "COMMON"},
  {6, "TLS"}, {10, "LOOS"}, {12, "HIOS"}, {13, "LOPROC"}, {15, "HIPROC"}};
std::map<uint8_t, std::string> id_to_bind = {{0, "LOCAL"}, {1, "GLOBAL"}, {2, "WEAK"},
   {10, "LOOS"}, {12, "LOPROC"}, {15, "HIPROC"}};
std::map<uint8_t, std::string> id_to_visibility = {{0, "DEFAULT"}, {1, "INTERNAL"}, {2, "HIDDEN"},
   {3, "PROTECTED"}, {4, "EXPORTED"}, {5, "SINGLETON"}, {6, "ELIMINATE"}};
std::map<uint16_t, std::string> id_to_ndx = {{0, "UND"}, {0xff00, "LORESERVE"},
{0xff01, "AFTER"}, {0xff02, "AMD64_LCOMMON"}, {0xff1f, "HIPROC"}, {0xff20, "LOOS"}, {0xff3f, "LOSUNW"},
{0xfff1, "ABS"}, {0xfff2, "COMMON"}, {0xffff, "XINDEX"}};

void error_exit(std::string message) {
    std::cerr << message << std::endl;
    exit(1);
}

std::string to_hex(int n, int len) {
    if (n == 0 && len == -1) return "0";
    std::string res = "";
    for (int i = 0; i < len || (len == -1 && n > 0); i++) {
        if ((n & 15) < 10) {
            res.push_back('0' + (n & 15));
        } else {
            res.push_back('a' + (n & 15) - 10);
        }
        n >>= 4;
    }
    reverse(res.begin(), res.end());
    return res;
}

FILE* open_file(const char* name, char* mode) {
    FILE* file = fopen(name, mode);
    if (file == nullptr) {
        error_exit("Couldn't open file: ");
    }
    return file;
}

void check_is_elf() {
    if (buf[0] != 0x7f || buf[1] != 0x45 || buf[2] != 0x4c || buf[3] != 0x46) {
        error_exit("Input file is not correct elf file");
    }
}

void check_bit_depth() {
    if (buf[E_OFFSET_BIT_DEPTH] != 1) {
        error_exit("Only 32-bit elf files are supported");
    }
}

void check_endianness() {
    if (buf[E_OFFSET_ENDIANNESS] != 1) {
        error_exit("Only little-endian elf files are supported");
    }
}

void check_isa() {
    if (buf[E_OFFSET_ISA] != RISCV_ID) {
        error_exit("Only RISC-V ISA is supported");
    }
}

uint32_t read32(uint32_t address) {
    return buf[address] | buf[address + 1] << 8 | buf[address + 2] << 16 | buf[address + 3] << 24;
}

uint16_t read16(uint32_t address) {
    return buf[address] | buf[address + 1] << 8;
}

uint32_t get_section_offset() {
    return read32(E_OFFSET_SECTION_HEADER);
}

uint16_t get_shstrndx() {
    return read16(E_OFFSET_SECTION_HEADER_TABLE_INDEX);
}

uint16_t get_eshnum() {
    return read16(E_OFFSET_ESHNUM);
}

bool is_strtab(uint32_t address) {
    return buf[address + SH_OFFSET_TYPE] == STRTAB_ID;
}

bool is_symtab(uint32_t address) {
    return buf[address + SH_OFFSET_TYPE] == SYMTAB_ID;
}

uint32_t get_sh_addr(uint32_t address) {
    return read32(address + 3 * 4);
}

bool is_progbits(uint32_t address) {
    return buf[address + SH_OFFSET_TYPE] == PROGBITS_ID && get_sh_addr(address) == main_address;
}

uint32_t get_sh_offset(uint32_t address) {
    return read32(address + SH_OFFSET_OFFSET);
}

uint32_t get_sh_name(uint32_t address) {
    return read32(address);
}

uint32_t get_sh_size(uint32_t address) {
    return read32(address + SH_OFFSET_SIZE);
}

std::string get_name(int address) {
    std::string result = "";
    for (uint32_t i = address; i < file_length && buf[i] != 0; i++) {
        result.push_back((char)buf[i]);
    }
    return result;
}

const uint8_t OPCODE_LEN = 7;
const uint8_t REG_SIZE = 5;
const uint8_t FUNCT3_LEN = 3;


const uint8_t REG_REG = 0b0110011;


const uint8_t ADD_SUB = 0b000;

const uint8_t ADD = 0b0000000;
const uint8_t SUB = 0b0100000;

const uint8_t SLL = 0b001;
const uint8_t SLT = 0b010;
const uint8_t SLTU = 0b011;
const uint8_t XOR = 0b100;
const uint8_t SR = 0b101;

const uint8_t SRL = 0b0000000;
const uint8_t SRA = 0b0100000;

const uint8_t OR = 0b110;
const uint8_t AND = 0b111;
const uint8_t MUL = 0b000;
const uint8_t MULH = 0b001;
const uint8_t MULHSU = 0b010;
const uint8_t MULHU = 0b011;
const uint8_t DIV = 0b100;
const uint8_t DIVU = 0b101;
const uint8_t REM = 0b110;
const uint8_t REMU = 0b111;

const uint8_t RV32M_FUNCT7 = 1;

std::map<uint16_t, std::string> reg_reg_mapping = {
    {ADD << FUNCT3_LEN, "add"},
    {SUB << FUNCT3_LEN, "sub"},
    {SLL, "sll"},
    {SLT, "slt"},
    {SLTU, "sltu"},
    {XOR, "xor"},
    {SR | SRL << FUNCT3_LEN, "srl"},
    {SR | SRA << FUNCT3_LEN, "sra"},
    {OR, "or"},
    {AND, "and"},
    {MUL | RV32M_FUNCT7 << FUNCT3_LEN, "mul"},
    {MULH | RV32M_FUNCT7 << FUNCT3_LEN, "mulh"},
    {MULHSU | RV32M_FUNCT7 << FUNCT3_LEN, "mulhsu"},
    {MULHU | RV32M_FUNCT7 << FUNCT3_LEN, "mulhu"},
    {DIV | RV32M_FUNCT7 << FUNCT3_LEN, "div"},
    {DIVU | RV32M_FUNCT7 << FUNCT3_LEN, "divu"},
    {REM | RV32M_FUNCT7 << FUNCT3_LEN, "rem"},
    {REMU | RV32M_FUNCT7 << FUNCT3_LEN, "remu"}
};

const uint8_t IMMEDIATE_ARITHMETIC = 0b0010011;
const uint8_t ADDI = 0b000;
const uint8_t SLTI = 0b010;
const uint8_t SLTIU = 0b011;
const uint8_t XORI = 0b100;
const uint8_t ORI = 0b110;
const uint8_t ANDI = 0b111;
const uint8_t SLLI = 0b001;
const uint8_t SRI = 0b101;

std::map<uint8_t, std::string> immediate_arithmetic_mapping = {
    {ADDI, "addi"},
    {SLTI, "slti"},
    {SLTIU, "sltiu"},
    {XORI, "xori"},
    {ORI, "ori"},
    {ANDI, "andi"},
    {SLLI, "slli"},
    {SRI, "sri"}
};


const uint8_t IMMEDIATE_MEMORY = 0b0000011;
const uint8_t LB = 0b000;
const uint8_t LH = 0b001;
const uint8_t LW = 0b010;
const uint8_t LBU = 0b100;
const uint8_t LHU = 0b101;

std::map<uint8_t, std::string> immediate_memory_mapping = {
    {LB, "lb"},
    {LH, "lh"},
    {LW, "lw"},
    {LBU, "lbu"},
    {LHU, "lhu"}
};

const uint8_t LUI = 0b0110111;
const uint8_t AUIPC = 0b0010111;
const uint8_t JAL = 0b1101111;

const uint8_t JALR = 0b1100111;
const uint8_t E = 0b1110011;
const uint16_t ECALL = 0b000000000000;
const uint16_t EBREAK = 0b000000000001;

const uint8_t BRANCH = 0b1100011;
const uint8_t BEQ = 0b000;
const uint8_t BNE = 0b01;
const uint8_t BLT = 0b100;
const uint8_t BGE = 0b101;
const uint8_t BLTU = 0b110;
const uint8_t BGEU = 0b111;

std::map<uint8_t, std::string> branch_mapping = {
    {BEQ, "beq"},
    {BNE, "bne"},
    {BLT, "blt"},
    {BGE, "bge"},
    {BLTU, "bltu"},
    {BGEU, "bgeu"}
};


const uint8_t STORE = 0b0100011;
const uint8_t SB = 0b000;
const uint8_t SH = 0b001;
const uint8_t SW = 0b010;

std::map<uint8_t, std::string> store_mapping = {
    {SB, "sb"},
    {SH, "sh"},
    {SW, "sw"}
};

std::string reg_mapping(uint8_t x) {
    if (x == 0) return "zero";
    else if (x == 1) return "ra";
    else if (x == 2) return "sp";
    else if (x == 3) return "gp";
    else if (x == 4) return "tp";
    else if (x >= 5 && x <= 7) return "t" + std::to_string(x - 5);
    else if (x >= 8 && x <= 9) return "s" + std::to_string(x - 8);
    else if (x >= 10 && x <= 17) return 'a' + std::to_string(x - 10);
    else if (x >= 18 && x <= 27) return "s" + std::to_string(x - 18 + 2);
    else if (x >= 28 && x <= 31) return "t" + std::to_string(x - 28 + 3);
}

struct instruction {
    uint32_t value;

    uint32_t opcode;
    uint32_t rd;
    uint32_t funct3;
    uint32_t rs1;
    uint32_t rs2;
    uint32_t funct7;

    instruction(uint32_t x) : value(x) {
        opcode = x & ((1 << OPCODE_LEN) - 1);
        x >>= OPCODE_LEN;
        rd = x & ((1 << REG_SIZE) - 1);
        x >>= REG_SIZE;
        funct3 = x & ((1 << FUNCT3_LEN) - 1);
        x >>= FUNCT3_LEN;
        rs1 = x & ((1 << REG_SIZE) - 1);
        x >>= REG_SIZE;
        rs2 = x & ((1 << REG_SIZE) - 1);
        x >>= REG_SIZE;
        funct7 = x;
    }

    uint16_t immediate12() {
        return value >> (32 - 12) & ((1 << 12) - 1);
    }

    uint32_t immediate20() {
        return value >> (32 - 20) & ((1 << 20) - 1);
    }

    uint32_t immediate7() {
    	return value >> (32 - 7) & ((1 << 7) - 1);
    }
};

int32_t get_jal_offset(uint32_t value) {
    value >>= 12;
    int32_t result = 0;
    result |= (value & ((1 << 8) - 1)) << 12;
    value >>= 8;
    result |= (value & 1) << 11;
    value >>= 1;
    result |= (value & ((1 << 10) - 1)) << 1;
    value >>= 10;
    result |= (value & 1) << 20;
    value >>= 1;
    result -= (1 << 21) * (result >> 20);
    return result;
}

int32_t get_branch_offset(uint32_t value) {
    value >>= 7;
    int32_t result = 0;
    result |= (value & 1) << 11;
    value >>= 1;
    result |= (value & ((1 << 4) - 1)) << 1;
    value >>= 4 + 3 + 5 + 5;
    result |= (value & ((1 << 6) - 1)) << 5;
    value >>= 6;
    result |= (value & 1) << 12;
    result -= (1 << 13) * (result >> 12);
    return result;
}

std::pair<std::string, std::string> parse_instruction(uint32_t x, uint32_t cur_address, std::map<uint32_t, std::string> functions_mapping) {
    std::string command_name = "";
    std::string arguments = "";
    instruction instr = instruction(x);
    int16_t local_immediate12 = instr.immediate12();
    local_immediate12 -= (1 << 12) * (local_immediate12 >> 11);
    switch (instr.opcode) {
    case REG_REG: {
        command_name = reg_reg_mapping[instr.funct3 | (instr.funct7 << FUNCT3_LEN)];
        arguments = reg_mapping(instr.rd) + ", " + reg_mapping(instr.rs1) + ", " + reg_mapping(instr.rs2);
        break;
    }
    case IMMEDIATE_ARITHMETIC: {
        command_name = immediate_arithmetic_mapping[instr.funct3];
        arguments = reg_mapping(instr.rd) + ", " + reg_mapping(instr.rs1) + ", " + std::to_string(local_immediate12);
        break;
    }
    case IMMEDIATE_MEMORY: {
        command_name = immediate_memory_mapping[instr.funct3];
        arguments = reg_mapping(instr.rd) + ", " + std::to_string(local_immediate12) + "(" + reg_mapping(instr.rs1) + ")";
        break;
    }
    case BRANCH: {
        int32_t offset = get_branch_offset(instr.value);
        uint32_t address_to_jump = cur_address + offset;
        command_name = branch_mapping[instr.funct3];
        arguments = reg_mapping(instr.rs1) + ", " + reg_mapping(instr.rs2) + ", " + to_hex(address_to_jump, -1) + " <" + functions_mapping[address_to_jump] + ">";
        break;
    }
    case STORE: {
        command_name = store_mapping[instr.funct3];
        arguments = reg_mapping(instr.rs2) + ", " + std::to_string(instr.rd | instr.immediate7() << 5) + "(" + reg_mapping(instr.rs1) + ")";
        break;
    }
    case LUI: {
        command_name = "lui";
        arguments = reg_mapping(instr.rd) + ", 0x" + to_hex(instr.immediate20() << 12, -1);
        break;
    }
    case AUIPC: {
        command_name = "auipc";
        arguments = reg_mapping(instr.rd) + ", " + std::to_string(instr.immediate20() << 12);
        break;
    }
    case JAL: {
        uint32_t address_to_jump = cur_address + get_jal_offset(instr.value);
        command_name = "jal";
        arguments = reg_mapping(instr.rd) + ", " + to_hex(address_to_jump, -1) + " <" + functions_mapping[address_to_jump] + ">";
        break;
    }
    case JALR: {
        command_name = "jalr";
        arguments = reg_mapping(instr.rd) + ", " + to_hex(instr.immediate12(), -1) + "(" + reg_mapping(instr.rs1) + ")";
        break;
    }
    case E: {
        if (instr.immediate12() == ECALL) {
            command_name = "ecall";
        } else {
            command_name = "ebreak";
        }
        break;
    }
    default:
        return std::make_pair("unknown_instruction", "");
    }
    return std::make_pair(command_name, arguments);
}

void add_mark(uint32_t x, uint32_t cur_address, uint32_t& mark_index, std::map<uint32_t, std::string>& functions_mapping) {
    std::string command_name = "";
    std::string arguments = "";
    instruction instr = instruction(x);
    int16_t local_immediate12 = instr.immediate12();
    local_immediate12 -= (1 << 12) * (local_immediate12 >> 11);
    if (instr.opcode == BRANCH) {
        int32_t offset = get_branch_offset(instr.value);
        uint32_t address_to_jump = cur_address + offset;
        if (functions_mapping.count(address_to_jump) == 0) {
            functions_mapping[address_to_jump] = "L" + std::to_string(mark_index);
            mark_index++;
        }
    } else if (instr.opcode == JAL) {
        uint32_t address_to_jump = cur_address + get_jal_offset(instr.value);
        if (functions_mapping.count(address_to_jump) == 0) {
            functions_mapping[address_to_jump] = "L" + std::to_string(mark_index);
            mark_index++;
        }
    }
}

void disassembly(uint32_t offset, std::map<uint32_t, std::string> functions_mapping, uint32_t code_size) {
    printf(".text\n");
    uint32_t sh_offset = get_sh_offset(offset);
    uint32_t sh_size = get_sh_size(offset);
    uint32_t cur = main_address;
    uint32_t mark_index = 0;
    for (uint32_t j = sh_offset; j < sh_offset + code_size; j += sizeof(uint32_t)) {
        add_mark(read32(j), cur, mark_index, functions_mapping);
        cur += sizeof(uint32_t);
    }
    cur = main_address;
    for (uint32_t j = sh_offset; j < sh_offset + code_size; j += sizeof(uint32_t)) {
        if (functions_mapping.count(cur) > 0) {
            printf("%08x   <%s>:\n", cur, functions_mapping[cur].c_str());
        }
        std::pair<std::string, std::string> instruction = parse_instruction(read32(j), cur, functions_mapping);
        printf("   %05x:\t%08x\t%7s\t%s\n", cur, read32(j), instruction.first.c_str(), instruction.second.c_str());
        cur += sizeof(int32_t);
    }
    printf("\n");
}

uint32_t get_file_size(std::string filename) {
    FILE* fd = open_file(filename.c_str(), "rb");
    fseek(fd, 0, SEEK_END);
	uint32_t file_size = ftello(fd);
	fclose(fd);
    return file_size;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        error_exit("Expected at least 3 arguments");
    }

    file_length = get_file_size(argv[1]);
    buf = (uint8_t*)malloc(file_length);

    FILE* input_file = open_file(argv[1], "rb");
    FILE* output_file = open_file(argv[2], "w");
    freopen(argv[2], "w", stdout);

    fread(buf, sizeof(uint8_t), file_length, input_file);

    check_is_elf();
    check_bit_depth();
    check_endianness();
    check_isa();

    uint32_t e_shoff = get_section_offset();
    uint16_t e_shnum = get_eshnum();

    std::map<uint32_t, std::string> function_mapping;

    for (uint32_t i = e_shoff, j = 0;i < file_length - ELF32_SHDR_SIZE; i += ELF32_SHDR_SIZE) {
        if (is_strtab(i)) {
            strtab_offset[j] = get_sh_offset(i);
            j++;
        }
    }

    for (uint32_t i = e_shoff; (i - e_shoff) / ELF32_SHDR_SIZE < e_shnum; i += ELF32_SHDR_SIZE) {
        uint32_t sh_name = get_sh_name(i);
        if (is_symtab(i)) {
            uint32_t sh_size = get_sh_size(i);
            uint32_t sh_offset = get_sh_offset(i);

            int32_t cnt = 0;

            for (uint32_t j = sh_offset; cnt < sh_size / SYMTAB_SIZE; j += SYMTAB_SIZE, cnt++) {
                uint32_t st_name = read32(j);
                if (st_name > 0) {
                    std::string name = get_name(strtab_offset[sh_name] + st_name);
                    if (id_to_type[buf[j + 12] & 0xf] == "FUNC") {
                        function_mapping[read32(j + 4)] = name;
                        if (name == "main") {
                            main_address = read32(j + 4);
                        }
                    }
                }
            }
        }
    }

    for (uint32_t i = e_shoff;i < file_length - ELF32_SHDR_SIZE; i += ELF32_SHDR_SIZE) {
        if (is_progbits(i)) {
            disassembly(i, function_mapping, get_sh_size(i));
            break;
        }
    }

    for (uint32_t i = e_shoff; (i - e_shoff) / ELF32_SHDR_SIZE < e_shnum; i += ELF32_SHDR_SIZE) {
        uint32_t sh_name = get_sh_name(i);
        if (is_symtab(i)) {
            uint32_t sh_size = get_sh_size(i);
            uint32_t sh_offset = get_sh_offset(i);
            printf(".symtab\nSymbol Value          	  Size Type     Bind     Vis         Index Name\n");

            int32_t cnt = 0;

            for (uint32_t j = sh_offset; cnt < sh_size / SYMTAB_SIZE; j += SYMTAB_SIZE, cnt++) {
                printf("[%4i] 0x%-15X %5i %-8s %-8s %-8s ", cnt, read32(j + 4),
                 read32(j + 8), id_to_type[buf[j + 12] & 0xf].c_str(), id_to_bind[buf[j + 12] >> 4].c_str(),
                 id_to_visibility[buf[j + 13]].c_str());
                uint32_t ndx_bytes = read16(j + 14);
                std::string ndx = std::to_string(ndx_bytes);
                if (id_to_ndx.find(ndx_bytes) != id_to_ndx.end()) {
                    ndx = id_to_ndx[ndx_bytes];
                }
                printf("%6s ", ndx.c_str());
                uint32_t st_name = read32(j);
                if (st_name > 0) {
                    std::string name = get_name(strtab_offset[sh_name] + st_name);
                    printf("%s", name.c_str());
                }
                printf("\n");
            }
        }
    }

    free(buf);
    fclose(input_file);

    return 0;
}
