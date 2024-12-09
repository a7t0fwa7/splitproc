#define BUFFER_SIZE 1024

enum class split_command : DWORD {
	GET_PID = 0,
    ALLOCATE_MEM,
	GENERATE_OPCODE,
    WRITE_MEM,    
	MEM_EXECUTABLE,
    THREAD_TRIGGER
};
