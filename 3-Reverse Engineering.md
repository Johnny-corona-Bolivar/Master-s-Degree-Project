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


- Ref 3:
  
  <img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/2ea6a822-6fed-485e-8ca8-ff5a5b9bf6ea" />
  
  As I understand it, here a loop is generated that will iterate through the string (for practical purposes, it is likely a while or for loop), and some calculations will also be performed during the iteration.
  The code jumps occur at line +69, which jumps to line +96 where the CMP instruction compares the values in ebp and 0x18, representing the previously defined variables. Then, we have the JL instruction, which indicates a jump if the first value is less   than the second. If the condition is not met, execution continues at line +71, where the value in edx is loaded into the memory address at ebp-0xc, which corresponds to a variable.


- Ref 4:

  <img width="600" height="267" alt="image" src="https://github.com/user-attachments/assets/8dfc6b1e-d51a-4462-911d-c706e1cb89ed" />

  In this image, we can see how the result is printed:

   - As verified earlier, the SUB instruction performs an unsigned subtraction.
   - PUSH: The PUSH instruction decrements the stack pointer (SP) by two bytes (note: on x86 typically 4 bytes in 32-bit) and then transfers the content onto the stack.
   - LEA: Loads the address of the operand. Here, it loads eax with the address at ebx-0x1992, which was defined at line +36, where it adds the string "Codigo generado" with a newline character.
   - The value is stored in eax in the following line.
   - Then, a CALL to printf@plt is made to print the result.
 

  - Ref 5:

  <img width="518" height="305" alt="image" src="https://github.com/user-attachments/assets/6ca19f0b-d32f-45e1-abe7-319c63b5104e" />

  "Here the program exits with the ret instruction."


 - Final Ref : "Compiling all the images, look  like this:"

 <img width="750" height="1000" alt="image" src="https://github.com/user-attachments/assets/66f8b630-6dbf-4435-9534-8bea2cba8e78" />


 - IDA:
 
  <img width="750" height="1000" alt="image" src="https://github.com/user-attachments/assets/2730a565-8524-4da0-99d0-81e882b7daf9" />

  ---



2. **Create a flowchart using the basic blocks**  
   Visualize the flow of execution to better understand the program structure.

   <img width="750" height="1000" alt="image" src="https://github.com/user-attachments/assets/24d31974-a1d4-4883-a2c9-de79edb6e2db" />
   <img width="650" height="969" alt="image" src="https://github.com/user-attachments/assets/fa00a38b-6752-4d8c-99ea-f09011bafaad" />
   <img width="650" height="501" alt="image" src="https://github.com/user-attachments/assets/318bd551-3969-4846-961f-28149830d0ac" />
   <img width="650" height="800" alt="image" src="https://github.com/user-attachments/assets/a91cd2d7-8473-4861-b6ef-11fde7517761" />


---

3. **Identify any control structures**  
   Determine if loops or conditional branches exist, and indicate which basic blocks participate in the control flow

  <img width="886" height="320" alt="image" src="https://github.com/user-attachments/assets/ab0fb818-5375-40f9-8ae8-7c42ea12b916" />

   
---

4. **Convert the entire function from assembly to C code**  
   Reconstruct the logic in the C programming language, maintaining the original structure and functionality.
   
   <img width="750" height="600" alt="image" src="https://github.com/user-attachments/assets/2d5ce6f4-3450-4083-8ea5-07f3e82c9afb" />

   "Code generated by IDA after decompiling it."

   <img width="750" height="530" alt="image" src="https://github.com/user-attachments/assets/a8c0b5aa-96c5-4ecc-9b55-2752e13fa14f" />

   "NOTE: I used a while loop, even though it was originally a for loop, because I found the while easier to work with and preferred to take a slightly different approach."

---


5. **Compile the generated C code and analyze the output**  
   Compile the program in 32-bit mode using the command:
   ```bash
   gcc source.c -o source -m32
After executing the compiled binary, capture and document the full output message printed to the screen.

"Note: When compiling the code and trying to switch to 32-bit mode, the code throws the following error:"

<img width="886" height="83" alt="image" src="https://github.com/user-attachments/assets/81baf356-331b-4608-a538-d3e14f667bca" />






---

6. **Modify the C source code to use a different input string**
Change the original string located at line <+36> to:
"Congratulations!"

"Code before changing the string"

 <img width="433" height="125" alt="image" src="https://github.com/user-attachments/assets/eefa615c-5d02-4509-adee-cbf74d09f951" />


 "Code after changing the string"

 <img width="839" height="88" alt="image" src="https://github.com/user-attachments/assets/a8ecd39d-2996-4646-9354-58eb9cd2415e" />
 <img width="591" height="314" alt="image" src="https://github.com/user-attachments/assets/08964701-14ce-4829-bffa-8bd9044d83e6" />






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
