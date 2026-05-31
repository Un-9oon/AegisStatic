# AegisStatic: CS-471 Reverse Engineering & Vulnerability Assessment
This document outlines the setup, deployment, and theoretical concepts for your final project defense of **AegisStatic** (the static triage and payload de-obfuscation engine).

---

## 1. Setup & Run Instructions
To configure and run AegisStatic on any machine (PC or server):

```bash
# 1. Navigate to the project directory
cd /home/we/.gemini/antigravity/scratch/

# 2. Run the automated Python setup script
python3 setup_aegis.py

# 3. Navigate into the application directory
cd obfuscation-engine

# 4. Activate the virtual environment
source .venv/bin/activate  # (On Windows CMD: .venv\Scripts\activate.bat)

# 5. Launch the Streamlit dashboard
streamlit run app.py
```
After executing, the dashboard will be available at: **`http://localhost:8501`**

---

## 2. Core Concepts (Defense Guide)

### Static Analysis
*   **Definition:** Analyzing a binary file without executing it.
*   **Why it matters:** It is safe, fast, and repeatable. Because the file is never loaded into a CPU execution context, the host system is protected from infection.

### Shannon Entropy
*   **Definition:** A mathematical measurement of data randomness (ranging from $0.0$ for completely predictable to $8.0$ for perfectly random).
*   **Why it matters:** Standard compiled code has structure (entropy between $4.5$ and $6.0$). Encrypted payloads or compressed packers have high entropy ($>6.5$). This difference helps locate hidden malicious sections.

### XOR Brute-Force
*   **Definition:** Trying all $255$ single-byte keys and $35$ common double-byte keys on high-entropy sections to decrypt hidden data.
*   **Why it matters:** Malware authors routinely hide command strings or domain names using simple XOR ciphers. The engine decodes these automatically.

### Capstone Disassembly & CFG
*   **Definition:** Translating machine code bytes back to assembly mnemonics statically, and parsing control flow jumps (`jmp`, `jz`, `call`, `ret`) to draw a visual graph of code execution pathways.
*   **Why it matters:** Allows security researchers to visually inspect logical structures (like anti-debugging checks or payload triggers) without manual debugging.

---

## 3. Evaluator Questions & Answers

#### Q1: "Why only parse PE files? What about Linux or Mac?"
*   **Answer:** "AegisStatic is specifically designed for the Portable Executable (PE) format—the native binary format for Windows executables, DLLs, and system drivers. Linux uses ELF and Mac uses Mach-O, which have completely different headers and section structures. AegisStatic's parser expects a Windows PE format; other formats are rejected safely during the initial file signature check."

#### Q2: "How does the engine handle packed files? Can it unpack them?"
*   **Answer:** "AegisStatic does not dynamically unpack binaries. Instead, it identifies packed files using Shannon entropy mapping, extracts the high-entropy sections, and uses brute-force XOR, Base64, and ROT13 heuristics to reveal strings or signatures within the packed blobs."

#### Q3: "What happens if a zip bomb is uploaded to crash your server?"
*   **Answer:** "The engine is immune to zip bombs. First, the uploader only accepts valid PE headers; a renamed zip file will fail the Initial PE check and be rejected. Second, when the engine processes high-entropy regions, it performs in-memory bitwise XOR decryption. Because we do not run decompression algorithms or write file extractions to the disk, the data size remains constant (e.g., a $50\text{ KB}$ input yields exactly a $50\text{ KB}$ output), preventing memory exhaustion."

#### Q4: "How does your decryption confidence scoring system work?"
*   **Answer:** "We use a heuristic score: $40\%$ weight on the ratio of printable ASCII characters and $60\%$ weight on high-value keyword density (matching terms like `cmd.exe`, `VirtualAlloc`, `http`, etc.). This ensures we only present meaningful decryptions to the user rather than random printable noise."
