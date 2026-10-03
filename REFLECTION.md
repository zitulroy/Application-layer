# Computer Networks — Transport Layer (Assignment 2)
## Reflection Document: Dual-Panel Activity & Transport-Layer Protocol Visualizer
**Author / Student:** Jitul Roy  
**Roll Number:** 202402021026  
**Course:** Computer Networks — Transport Layer  
**Live Working Demo:** [https://application-layer-six.vercel.app/](https://application-layer-six.vercel.app/)  
**GitHub Repository:** [https://github.com/zitulroy/Application-layer](https://github.com/zitulroy/Application-layer)  
**AI Platform:** Google Antigravity | **Model:** Gemini 3.8 Flash (High Reasoning)  

---

### 1. Choice of Agentic AI Platform & Model
For this assignment, **Google Antigravity** paired with **Gemini 3.8 Flash (High Reasoning)** was selected. 

#### Why this platform and model were chosen:
1. **Direct Workspace Integration**: Antigravity operates as an agentic pair-programmer with deep visibility across the repository (`index.html`, `styles.css`, `script.js`, `README.md`). Rather than copying snippets between a web chat and an IDE, the agent inspects, modifies, and validates changes directly in the workspace.
2. **High-Reasoning Capabilities**: Accurately simulating TCP finite state machines (RFC 793 / RFC 9293), cumulative byte-stream numbering, and dual-layer event synchronization requires mathematical consistency and protocol knowledge. Gemini 3.8 Flash with high reasoning handles RFC edge cases reliably while maintaining rapid iteration cycles.
3. **Integrated Terminal & Headless Verification**: Antigravity allows executing shell commands and headless browser runs (via Microsoft Edge) to verify that sequence diagrams, packet inspector modals, and split-view synchronization render cleanly without console errors.

---

### 2. Synchronization Architecture Between Application (L7) and Transport (L4)
The primary challenge of Assignment 2 was keeping the Left Panel (Activity Driver), Right Panel Transport Layer (L4 Packets), and Application Layer (L7 Transactions) synchronized in lockstep.

```
+-----------------------------------------------------------------------------------+
| LEFT PANEL (User Actions)                                                         |
|  [Browsing] URL + Visit | [Mail] To/Subject/Body + Send | [Streaming] TCP/UDP     |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| UNIFIED PROTOCOL ENGINE (script.js)                                              |
|  - Generates L7 Transactions: [{id: 0, head: "DNS Query", lines: [...]}, ...]    |
|  - Generates L4 Packets: [{seq: 1000, ack: 0, flags: ["SYN"], l7Index: 2}, ...]  |
+-----------------------------------------------------------------------------------+
                                         |
                     +-------------------+-------------------+
                     |                                       |
                     v                                       v
+------------------------------------+   +------------------------------------+
| L4 Sequence Track (msgTrack L4)    |   | L7 Transaction Track (msgTrack L7) |
| Active Packet: Frame #i            |   | Highlighted Event: pkt[i].l7Index  |
| Flags: [SYN], [ACK], [PSH], [FIN]  |   | DNS Resolution / HTTP / SMTP       |
+------------------------------------+   +------------------------------------+
                     |                                       |
                     +-------------------+-------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| REAL-TIME TELEMETRY & PACKET INSPECTOR                                            |
| Client: ESTABLISHED | Server: ESTABLISHED | cwnd: 4 MSS | rwnd: 64 KB             |
| 32-bit RFC Header Grid | Exact Byte Math (Seq 1001 + 185B -> Next Ack 1186)      |
+-----------------------------------------------------------------------------------+
```

#### Synchronization Mechanism:
1. **Hierarchical Data Binding**: Every Transport packet object in `script.js` contains a pointer `l7Index` referencing its parent Application transaction. For example, during Browsing, the 3 handshake packets (`SYN`, `SYN-ACK`, `ACK`) all point to `l7Index: 2` ("TCP 3-Way Handshake").
2. **Single Playback Clock**: A single integer `cursor` controls the active frame. Stepping forward (`›`), backward (`‹`), pausing (`⏸`), or replaying (`↺`) updates the cursor.
3. **Synchronized Dual-Track Rendering**:
   - The L4 track highlights the specific packet with flags and byte accounting.
   - The L7 track highlights the active application transaction using a glowing accent border.
4. **Three Distinct Viewing Modes**: The view switcher allows the user to view:
   - **Transport (L4)**: Detailed packet sequence diagram with exact sequence/ack fields.
   - **Application (L7)**: High-level human-readable protocol messages.
   - **Split View**: Both panels side-by-side or stacked, maintaining live synchronized highlighting.

---

### 3. What the AI Got Wrong & How It Was Corrected
During development, the AI made several classic networking and state-machine assumptions that had to be identified and corrected:

| Error Category | AI Initial Behavior | RFC Standard & Applied Correction |
| :--- | :--- | :--- |
| **SYN/FIN Sequence Space** | Treated `SYN` and `FIN` as consuming 0 sequence bytes because their payload `Length = 0`. This caused the first HTTP GET to reuse `Seq = 1000`. | **RFC 793 Violation**: `SYN` and `FIN` control flags consume exactly **1 sequence number in sequence space**. Corrected sequence logic: `cSeq += 1` upon sending SYN, so HTTP GET begins at `Seq = 1001` and server ACKs `1001`. FIN also increments sequence counter by 1. |
| **Cumulative ACK Calculation** | Set `Ack = Seq` (acknowledging the start byte of the received frame), rather than acknowledging the *next expected byte*. | **RFC 9293 Rule**: A TCP ACK specifies the *next sequence number the receiver expects to receive* (`Ack = Seq + Length`). Corrected: Client sends 185-byte HTTP GET at `Seq = 1001`; Server responds with `Ack = 1001 + 185 = 1186`. Pure ACKs (`Len = 0`) do not advance sequence space. |
| **Connection Teardown Handshake** | Modeled an abrupt 2-packet teardown (`FIN` -> `ACK`), omitting the server's own FIN packet and leaving the connection half-closed. | **Full 4-Way Teardown**: Corrected to model standard bidirectional close: `Client FIN, ACK` (`FIN_WAIT_1`, Server enters `CLOSE_WAIT`) -> `Server ACK` (`FIN_WAIT_2`) -> `Server FIN, ACK` (`LAST_ACK`, Client enters `TIME_WAIT`) -> `Client final ACK` (Server enters `CLOSED`, Client enters `TIME_WAIT` 2MSL). |
| **Streaming Protocol Scope** | Initially only supported HTTP/TCP for video streaming, omitting datagram comparisons. | **TCP vs UDP Comparison Added**: Added an interactive Transport Protocol toggle (`TCP (HLS/DASH)` vs `UDP (Live RTP)`) to illustrate reliable byte-stream transmission versus stateless, low-overhead datagram delivery. |

---

### 4. Key Differences Observed Across Transport-Layer Flows

#### A. Web Browsing (`HTTP/1.1 over TCP`)
- **Lifecycle**: Short-lived, request-response pattern.
- **Transport Profile**: Handshake (3 packets) -> HTTP GET (1 packet) -> Server ACK -> HTTP 200 chunked response (2 packets) -> Client ACK -> Full 4-way FIN teardown.
- **Key Characteristics**: Highly asymmetric payload (small request of ~185 bytes vs larger HTML response). Handshake and teardown overhead represent a significant percentage of total packets (~50% of frames).

#### B. Mail Transmission (`SMTP over TCP`)
- **Lifecycle**: Conversational, interactive lockstep sequence over a long-lived TCP connection.
- **Transport Profile**: Server speaks first (`220 ESMTP`), followed by alternating command-reply pairs (`EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`), with each message flagged with `[PSH, ACK]`.
- **Key Characteristics**: Chatty protocol requiring multiple Round-Trip Times (RTTs). Frequent small segments make SMTP highly latency-sensitive compared to bulk HTTP transfers.

#### C. Video Streaming (`HLS over TCP` vs `Live RTP over UDP`)
- **TCP (HLS/DASH)**:
  - Demonstrates **persistent connection reuse** (HTTP Keep-Alive): Segment `seg001.ts` is requested over the existing TCP stream without undergoing another 3-way handshake.
  - Demonstrates **Congestion Window (`cwnd`) dynamics**: Slow Start ramps `cwnd` from 1 MSS -> 2 MSS -> 4 MSS -> 8 MSS -> 16 MSS, saturating available bandwidth while honoring receiver window (`rwnd = 64 KB`).
- **UDP (Live RTP Comparison)**:
  - **Zero connection setup (0-RTT)**: Media datagrams stream immediately without SYN/ACK handshake.
  - **No Head-of-Line Blocking**: Individual datagram loss does not stall subsequent frame decoding.
  - **Low Protocol Overhead**: Minimal 8-byte UDP header compared to 20-60 byte TCP headers.

---

### 5. Summary & Key Takeaways
Building this dual-panel visualizer highlighted how application-layer requests translate into transport-layer packets. Agentic AI tools accelerate frontend visualizer scaffolding, but ensuring strict protocol correctness (sequence space math, TCP finite-state machine transitions, and persistent keep-alive semantics) requires continuous human verification against RFC standards.
