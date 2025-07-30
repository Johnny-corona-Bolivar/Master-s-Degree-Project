# 🧠 Assembly to C Reverse Engineering and Control Flow Analysis

This project is part of a cybersecurity master's program, focusing on reverse engineering and control flow analysis of a compiled assembly routine. The goal is to understand low-level operations, extract logic from raw assembler, convert it to C code, and analyze control structures through visual representations.

---
## 🎯 Objectives

- Break down the assembly code into basic blocks using jump and comparison instructions.
- Build a flowchart of control flow using IDA and external diagram tools.
- Identify control structures such as loops and conditionals within the function.
- Reconstruct the logic of the function and rewrite it in C language.
- Compile the code using 32-bit mode and observe the output.
- Modify the input string in the code and recompile to analyze behavioral changes.

---

## 🧠 Project Overview

This project analyzes a compiled x86 assembly function and reconstructs its logic in the C programming language. The exercise involves breaking down the assembly into basic blocks, understanding data flow and control structures, building a flowchart, and compiling the equivalent C code. This process reinforces knowledge in low-level programming, binary analysis, and compiler behavior.

## 📝 Task Instructions

1. **Divide the code into basic blocks**  
   Take into account the jump instructions within the function and split the lines accordingly into logical blocks of code.

2. **Create a flowchart using the basic blocks**  
   Visualize the flow of execution to better understand the program structure.

3. **Identify any control structures**  
   Determine if loops or conditional branches exist, and indicate which basic blocks participate in the control flow.

4. **Convert the entire function from assembly to C code**  
   Reconstruct the logic in the C programming language, maintaining the original structure and functionality.

5. **Compile the generated C code and analyze the output**  
   Compile the program in 32-bit mode using the command:
   ```bash
   gcc source.c -o source -m32
After executing the compiled binary, capture and document the full output message printed to the screen.

6. **Modify the C source code to use a different input string**
Change the original string located at line <+36> to:
"Congratulations!"

**Essembly Code**

<img width="315" height="822" alt="image" src="https://github.com/user-attachments/assets/9a2102d2-3f1b-492c-8e67-de9558a09461" />

<img width="396" height="585" alt="image" src="https://github.com/user-attachments/assets/ca1a31c9-1fbb-4100-937e-c4c3a34f68ae" />


---



## 🔧 Tools & Technologies Used

- **IDA Free / IDA Pro** – For static analysis and flowchart generation  
- **OnlineGDB** – For writing, compiling, and testing C code without needing local setup  
- **GCC (-m32)** – To compile C code in 32-bit mode  
- **mymap.ai** – To assist in building a logical flowchart  
- **Copilot** – Used to help structure clean and functional C code from assembly logic  
  
---

## 🔍 Steps taken

 The following steps were required for this reverse engineering project:


1. **Divide the code into basic blocks**  
   Take into account the jump instructions within the function and split the lines accordingly into logical blocks of code.

- Ref 1: "Program initialization where variables are initialized."

   <img width="560" height="388" alt="image" src="https://github.com/user-attachments/assets/d557295e-c9ca-48ba-b335-c140560fc9f1" />
- Ref 2:
  "Taking into account line +29: MOV, where the data transfer begins, we can determine..."
  <img width="560" height="388" alt="image" src="https://github.com/user-attachments/assets/9c92644f-0a5a-4654-a2d2-97c751f12498" />
  
  "By analyzing the code, it can be determined that this is the section where a variable is initialized — specifically a char variable, since it stores a string."

  We have:
  char variable = "string";
  Then, by observing the use of DWORD PTR, we can determine that these refer to integer values. Since there are three instances, we can infer they represent three integer variables:
  int var1 = value1;
  int var2 = value2;
  int result;
  
  Instruction breakdown:
- LEA (Load Effective Address): Loads the address of the operand, in this case, the string.
- SUB: Performs an unsigned subtraction (note: often confused, but not multiplication; SUB is subtraction).
- MOV: Transfers data between registers or memory and registers.
- PUSH: Increments the stack pointer and places the value on the stack (in 32-bit systems, by 4 bytes).
- CALL: Calls a function, in this case, the default strlen@plt, which, similar to other languages, loads the routine to calculate the length of a string.
- ADD: Adds the operands and stores the result in the destination.



 

---


## 🛡️ Security Concepts Reinforced

- Understanding how compilers translate high-level logic to assembly
- Recognizing common loop and arithmetic operations at a low level
- Reverse engineering binary code flow through registers and memory offsets
- Identifying potential issues in manually converted low-level routines

---

## 📚 Skills Acquired

- Manual decomposition of assembly code into basic blocks  
- Reconstruction of x86-32 assembly logic into valid and functional C code  
- Use of IDA and visual tools to build a control flow diagram  
- Compilation with `gcc -m32` and troubleshooting architecture-specific errors  
- Low-level understanding of function prologue, epilogue, and memory operations  
- Modification of string literals and understanding their effect on output  

---
