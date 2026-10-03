# AI Usage Log & Development Artifacts
## Computer Networks — Transport Layer (Assignment 2)

**Author:** Jitul Roy  
**Roll Number:** 202402021026  
**Course:** Computer Networks — Transport Layer  
**Live Demo:** [https://application-layer-six.vercel.app/](https://application-layer-six.vercel.app/)  
**GitHub Repository:** [https://github.com/zitulroy/Application-layer](https://github.com/zitulroy/Application-layer)  
**Agentic AI Platform:** Google Antigravity  
**Model:** Gemini 3.8 Flash (High Reasoning)  

---

### 1. Platform & Model Overview
- **Development Tool:** Google Antigravity (Advanced Agentic Coding Environment)
- **Model Used:** Gemini 3.8 Flash (configured with High Reasoning mode)
- **Role in Workflow:** Architectural planning, dual-panel synchronization design, RFC 793 / RFC 9293 state-machine generation, code refactoring across `index.html`, `styles.css`, and `script.js`, automated test capture via headless Edge, and document compilation.

---

### 2. Prompt History & Interaction Cycles

#### Cycle 1: Architecture & Starter Prompt Adaptation
- **User Request:**
  > Extend the dual-panel web dashboard built in Assignment 1 so that, for the same three application-layer activities (Browsing, Mail, and Streaming), the user can also visualize the underlying Transport-layer protocol exchanges (primarily TCP, with optional UDP / QUIC where relevant) in real time. Keep the left panel unchanged in functionality. The right panel must support two synchronized views: Application Layer (L7) and Transport Layer (L4), plus a Split View.
- **Agent Analysis & Plan:**
  - Evaluated existing Assignment 1 codebase: pure frontend HTML5, modern CSS with dark/light theme, and vanilla JavaScript event-driven architecture.
  - Formulated a unified state model where low-level Transport frames maintain direct foreign keys (`l7Index`) to high-level Application transactions.
  - Implemented view switcher tabs (`Transport (L4)`, `Application (L7)`, `Split View (Both)`).

#### Cycle 2: Transport Protocol Engineering & RFC Verification
- **User / Rubric Directive:**
  > Visualizations must show exact messages / flags (SYN, SYN-ACK, ACK, PSH, FIN, RST), sequence numbers, acknowledgment numbers, window size, flags, and state transitions. Ensure strict RFC correctness.
- **Agent Action & Iteration:**
  - Designed the packet array generator for Web Browsing, Mail, and Streaming.
  - Identified and corrected AI-generated sequence number bugs:
    - *Correction:* SYN and FIN flags each consume 1 sequence space (phantom byte rule).
    - *Correction:* Acknowledgment numbers must acknowledge the next expected sequence byte (`Ack = Seq + Len`).
    - *Correction:* Standardized 4-way FIN/ACK connection teardown.
  - Modeled Congestion Window (`cwnd`) growth during streaming (Slow Start: 1 -> 2 -> 4 -> 8 -> 16 MSS).

#### Cycle 3: Interactive Inspector & Protocol Comparison (Extra Credit)
- **User / Rubric Directive:**
  > Compare reliable byte-stream delivery (TCP) versus datagram delivery (UDP). Highlight key fields (Seq, Ack, Win, Flags, Length) and support progressive reveal.
- **Agent Action:**
  - Implemented the 32-bit TCP / 8-byte UDP RFC Header Box Inspector with clear mathematical breakdown cards explaining sequence number math.
  - Added the Transport Protocol selector in the Streaming activity: `TCP (HLS/DASH)` vs `UDP (Live RTP)`.
  - Added speed controls (1x, 1.5x, 2x) and keyboard navigation (Spacebar, Left/Right arrows).

#### Cycle 4: Automated Validation, Deliverables & Submission Assets
- **User Request:**
  > git add commit and create a pdf mentioning about everything that u make changes in this session live link: https://application-layer-six.vercel.app/ and github link: https://github.com/zitulroy/Application-layer, make sure that link should be clickable, author: Jitul Roy, roll no = 202402021026
- **Agent Action:**
  - Embedded deep-link query parameter handling (`?act=...&step=...&view=...&proto=...`).
  - Generated full-page high-resolution screenshots for all activities in `screenshots/`.
  - Compiled professional reflection documents:
    - `REFLECTION.md` (Markdown)
    - `reflection_document.docx` (Word via `python-docx` with clickable hyperlinks)
    - `reflection_document.pdf` (2-page print-ready PDF generated via Edge headless with clickable hyperlinks).
  - Updated `README.md` with complete architecture, run instructions, and live deployment links.

---

### 3. Summary of Applied Corrections

| Area | Initial AI Output | Human / RFC Corrected Output |
| :--- | :--- | :--- |
| **SYN Sequence Space** | `Seq = 1000` reused for subsequent HTTP GET | Incremented `cSeq += 1` on SYN; HTTP GET starts at `Seq = 1001` (RFC 793) |
| **ACK Numbering** | `Ack = Seq` (acknowledging current frame) | `Ack = Seq + Len` (acknowledging next expected byte, RFC 9293) |
| **Connection Teardown** | Abrupt 2-packet client-initiated close | Full 4-way bidirectional FIN/ACK handshake with standard TCP states |
| **Streaming Model** | Only modeled HTTP/TCP | Added interactive TCP vs UDP comparison toggle for video streaming |

---

### 4. Verification Evidence
All source files (`index.html`, `styles.css`, `script.js`) were verified with zero syntax errors (`node -c script.js` passed with code 0) and validated visually via headless Edge rendering.
