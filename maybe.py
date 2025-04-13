import socket
import struct
import sys # Added for error printing

HOST = '0.0.0.0'
PORT = 9100
# --- Improved Attribute Encoding Helper ---

def _encode_attribute(tag, name, value):
    """Encodes a single IPP attribute (tag, name, value)."""
    name_bytes = name.encode('utf-8')
    packed_data = bytearray()
    packed_data.append(tag)
    packed_data.extend(struct.pack(">H", len(name_bytes)))
    packed_data.extend(name_bytes)

    value_bytes = b''
    value_len = 0

    # Determine value encoding based on tag (simplified examples)
    # See RFC 8010 Section 3.5.1 for tag types
    if tag in (0x47, 0x48, 0x44, 0x42, 0x45, 0x41): # charset, naturalLanguage, text, name, uri, keyword (strings)
        if isinstance(value, str):
            value_bytes = value.encode('utf-8')
        elif isinstance(value, bytes): # Allow pre-encoded bytes for strings
             value_bytes = value
        else:
             raise TypeError(f"Attribute '{name}': Expected string or bytes for tag {tag:#02x}, got {type(value)}")
        value_len = len(value_bytes)
    elif tag in (0x21, 0x22): # integer, enum
        if not isinstance(value, int):
             raise TypeError(f"Attribute '{name}': Expected int for tag {tag:#02x}, got {type(value)}")
        # RFC 8010 3.5.2/3.5.3: MUST be 4 bytes (signed integer)
        value_bytes = struct.pack(">i", value) # Pack as signed int
        value_len = 4
    elif tag == 0x23: # boolean
        if not isinstance(value, bool):
             raise TypeError(f"Attribute '{name}': Expected bool for tag {tag:#02x}, got {type(value)}")
        # RFC 8010 3.5.4: MUST be 1 byte
        value_bytes = struct.pack(">b", 1 if value else 0)
        value_len = 1
    # Add more type handlers here if needed (dateTime, resolution, rangeOfInteger, etc.)
    else:
        # Fallback for types not explicitly handled (use with caution)
        # Assume value is pre-encoded bytes if not string/int/bool
        if isinstance(value, str):
            value_bytes = value.encode('utf-8')
            value_len = len(value_bytes)
        elif isinstance(value, bytes):
            value_bytes = value
            value_len = len(value_bytes)
        else:
             raise TypeError(f"Attribute '{name}': Unsupported value type {type(value)} for tag {tag:#02x}")

    packed_data.extend(struct.pack(">H", value_len))
    packed_data.extend(value_bytes)
    return bytes(packed_data)


def build_ipp_response(request_id, requested_operation_id=None):
    """Builds a basic IPP Get-Printer-Attributes like response."""
    version = b'\x01\x01' # IPP/1.1
    # Decide status code based on (optional) operation check
    # Example: Only support Get-Printer-Attributes (0x000B) for now
    OP_GET_PRINTER_ATTRIBUTES = 0x000B
    if requested_operation_id is not None and requested_operation_id != OP_GET_PRINTER_ATTRIBUTES:
        status_code = b'\x05\x01' # server-error-operation-not-supported
        print(f"Unsupported operation requested: {requested_operation_id:#04x}", file=sys.stderr)
    else:
         status_code = b'\x00\x00' # successful-ok

    req_id = struct.pack(">I", request_id)

    response = bytearray()
    response += version + status_code + req_id

    # --- Attribute Groups ---
    # 1. Operation Attributes Group
    response.append(0x01) # operation-attributes-tag
    response.extend(_encode_attribute(0x47, "attributes-charset", "utf-8"))
    response.extend(_encode_attribute(0x48, "attributes-natural-language", "en"))
    # Could add 'status-message' attribute here if status_code != successful-ok

    # 2. Printer Attributes Group (Only if operation was successful/supported)
    if status_code == b'\x00\x00':
        response.append(0x04) # printer-attributes-tag

        # --- Using the new _encode_attribute function ---
        # Text/Name/Keyword/URI attributes (Strings)
        response.extend(_encode_attribute(0x42, "printer-name", "PetShopPrinter")) # nameWithoutLang
        response.extend(_encode_attribute(0x44, "printer-location", "CTF Lab")) # textWithoutLang
        response.extend(_encode_attribute(0x44, "printer-make-and-model", "VirtualPrinter 1.0"))
        response.extend(_encode_attribute(0x44, "printer-device-id", "MFG:Fake;MDL:FakeModel;CMD:FakeLang;"))
        response.extend(_encode_attribute(0x44, "printer-state-message", "Ready to print."))
        response.extend(_encode_attribute(0x41, "printer-state-reasons", "none")) # keyword

        # --- FIX for printer-uri-supported ---
        # Ideally, determine this dynamically or from config. Hardcoding for now.
        # Ensure the IP/hostname is actually reachable by clients.
        printer_uri = f"ipp://{HOST}:{PORT}/ipp/print" # Use HOST, might need adjustment if HOST='0.0.0.0'
        # If HOST is '0.0.0.0', you might need to get the actual interface IP or use hostname
        try:
            # Attempt to get a non-loopback hostname/IP if HOST is '0.0.0.0'
            # This is a simple approach, might not work in all network setups
            actual_host = HOST
            if actual_host == '0.0.0.0':
                actual_host = socket.getfqdn() # Or socket.gethostbyname(socket.gethostname())
            printer_uri = f"ipp://{actual_host}:{PORT}/ipp/print"
        except socket.gaierror:
             # Fallback if hostname lookup fails
             print("Warning: Could not determine FQDN, using HOST in printer-uri-supported.", file=sys.stderr)
             # You might need to hardcode a known reachable IP/hostname here instead
             # printer_uri = "ipp://your-server-ip-or-hostname:9100/ipp/print"

        response.extend(_encode_attribute(0x45, "printer-uri-supported", printer_uri)) # uri

        # Integer/Enum attributes (Integers)
        response.extend(_encode_attribute(0x21, "printer-type", 4))  # integer (provide actual int)
        response.extend(_encode_attribute(0x22, "printer-state", 3)) # enum (provide actual int, 3=idle)

    # --- FIX: Add End of Attributes Tag ---
    response.append(0x03) # end-of-attributes-tag

    return bytes(response) # Return immutable bytes

def handle_client(conn, addr):
    print(f"Connection from {addr}")
    with conn:
        # It's better to receive in a loop until full HTTP headers are read,
        # or at least enough for IPP header, but for simplicity, assume one recv is enough
        # for this basic example. A robust server needs proper HTTP parsing.
        try:
            # Receive enough data to get the IPP header at least
            # IPP header: version(2) + op/status(2) + req_id(4) = 8 bytes
            # Need more if reading requested attributes etc.
            request_data = conn.recv(4096)
            if not request_data:
                print("Connection closed by client before sending data.")
                return

            # Basic parsing attempt (assuming HTTP POST request)
            # Find the end of HTTP headers (\r\n\r\n)
            eoh = request_data.find(b'\r\n\r\n')
            if eoh == -1:
                print("Error: Did not receive complete HTTP headers.", file=sys.stderr)
                # Could send HTTP 400 Bad Request here
                return

            ipp_request_body = request_data[eoh + 4:]

            if len(ipp_request_body) < 8:
                print(f"Error: Received insufficient data for IPP header ({len(ipp_request_body)} bytes).", file=sys.stderr)
                # Could send HTTP 400 Bad Request here
                return

            # --- Parse Request ID and Operation ID ---
            # version_recv = ipp_request_body[0:2] # Could check this
            operation_id = struct.unpack(">H", ipp_request_body[2:4])[0]
            request_id = struct.unpack(">I", ipp_request_body[4:8])[0]

            print(f"Received IPP request: Operation={operation_id:#04x}, RequestID={request_id}")
            # print(request_data.decode(errors='ignore')) # Can be noisy

            # --- Build Response based on request ---
            ipp_response = build_ipp_response(request_id, operation_id)

            # --- Send HTTP Response ---
            http_response = (
                b"HTTP/1.1 200 OK\r\n"  # Always 200 OK for HTTP layer in IPP
                b"Content-Type: application/ipp\r\n"
                b"Content-Length: " + str(len(ipp_response)).encode('ascii') + b"\r\n"
                b"Connection: close\r\n"
                b"\r\n" +
                ipp_response
            )
            conn.sendall(http_response)
            print(f"Sent IPP response (Status: {ipp_response[2:4].hex()}, Length: {len(ipp_response)}).") # Show IPP status

        except struct.error as e:
            print(f"Error unpacking IPP header: {e}", file=sys.stderr)
        except ConnectionResetError:
             print("Connection reset by peer.", file=sys.stderr)
        except Exception as e:
            print(f"Error handling client {addr}: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)


# --- Main Server Loop ---
if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((HOST, PORT))
        except OSError as e:
            print(f"Error binding to {HOST}:{PORT} - {e}", file=sys.stderr)
            sys.exit(1)

        s.listen(5)
        print(f"IPP Server listening on {HOST}:{PORT}...")

        while True:
            try:
                conn, addr = s.accept()
                # Simple one-thread-per-connection model (not scalable for high load)
                # Consider using threading or asyncio for concurrent handling
                handle_client(conn, addr)
            except KeyboardInterrupt:
                 print("\nServer shutting down.")
                 break
            except Exception as e:
                 print(f"Error accepting connection: {e}", file=sys.stderr)
