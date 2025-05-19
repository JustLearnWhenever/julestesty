// Global variable to store the currently connected IP
let connectedIp = null;
// Global variable for the current mission state
let currentGameMission = null;
// Global variable for simulated file systems
let simulatedFileSystems = {};
// Global variable for the current path on the remote system
let currentPath = null;

const educationalContent = {
    "dll hijacking": {
        title: "DLL Hijacking",
        what_it_is: "DLL Hijacking is a technique where an attacker places a malicious DLL in a location where an application is expected to load a legitimate DLL. If the application loads the malicious DLL, the attacker's code is executed.",
        how_it_works: "Applications often search for DLLs in a specific order (e.g., application directory, system directories). If an application searches its own directory first, and that directory is writable by the attacker, a malicious DLL with the same name as a legitimate one can be planted there.",
        real_world_tools: "Metasploit Framework, custom scripts.",
        prevention_detection: [
            "Developers: Ensure applications load DLLs from trusted, absolute paths. Use `SetDllDirectory(\"\")` or `AddDllDirectory` to control DLL search paths. Implement manifest files specifying DLL dependencies.",
            "System Admins: Monitor for unexpected DLL loads or file writes to application directories. Use application whitelisting. Keep systems patched."
        ]
    },
    "reflective dll injection": {
        title: "Reflective DLL Injection",
        what_it_is: "A more advanced and stealthy method of DLL injection where the malicious DLL is loaded directly from memory into a host process, rather than from disk.",
        how_it_works: "The injector allocates memory in the target process, copies the DLL's code into that memory, and then calls the DLL's entry point (often `ReflectiveLoader` for specially crafted DLLs, or by resolving `DllMain` after manually mapping the DLL in memory). This avoids leaving traces on the file system.",
        real_world_tools: "Cobalt Strike, Metasploit Framework, various custom loaders.",
        prevention_detection: [
            "Developers: Harder to prevent directly by an application.",
            "System Admins: Monitor for unusual memory allocations and thread creation in processes. Use Endpoint Detection and Response (EDR) tools that can analyze memory and detect in-memory threats. Scrutinize processes that don't have corresponding image files on disk. Look for signs of manual PE header mapping in memory."
        ]
    }
    // Add more topics here later
};

document.addEventListener('DOMContentLoaded', () => {
    const terminal = document.getElementById('terminal'); // Main terminal container
    const output = document.getElementById('output');
    const commandInput = document.getElementById('commandInput');
    const inputLine = document.getElementById('input-line'); // The div containing prompt and input

    // Function to add a line to the output (for command results)
    function addOutputLine(text) {
        const lineElement = document.createElement('div');
        // Using innerHTML to allow for <br> for newlines from content
        lineElement.innerHTML = text.replace(/\n/g, '<br>');
        output.appendChild(lineElement);
        // Auto-scroll handled after command processing
    }

    // Helper function to normalize paths (ensure trailing slash and consistent slashes)
    function normalizePath(pathStr) {
        if (!pathStr) return null;
        let normalized = pathStr.replace(/\//g, '\\'); // Replace forward slashes with backslashes
        if (!normalized.endsWith('\\')) {
            normalized += '\\';
        }
        if (!normalized.startsWith('C:\\')) { // Assuming C: drive for simplicity
            normalized = 'C:\\' + normalized.replace(/^\\+/, '');
        }
        return normalized;
    }
    
    // Helper function to get the object for a given path in the simulated file system
    function getPathObject(ip, path) {
        if (!ip || !path || !simulatedFileSystems[ip]) return null;
        const pathParts = normalizePath(path).split('\\').filter(p => p); // Filter out empty parts
        let currentLevel = simulatedFileSystems[ip];
        for (let i = 0; i < pathParts.length; i++) {
            const part = pathParts[i];
            if (currentLevel && currentLevel[part] && currentLevel[part].type === 'dir') {
                if (i === pathParts.length -1) return currentLevel[part].children; // Return children of target dir
                 currentLevel = currentLevel[part].children;
            } else if (currentLevel && currentLevel[part] && currentLevel[part].type === 'file' && i === pathParts.length -1) {
                return currentLevel[part]; // Return file object
            }
            else {
                // Special case for root "C:\"
                if (pathParts.length === 1 && pathParts[0].toUpperCase() === "C:") {
                    return currentLevel["C:\\"].children;
                }
                return null; // Path not found or not a directory
            }
        }
        return currentLevel;
    }

    // Function to handle command processing (moved existing switch logic here)
    function handleCommand(fullCommand) {
        const commandParts = fullCommand.split(' ');
        const command = commandParts[0].toLowerCase(); // Commands are case-insensitive
        const args = commandParts.slice(1);

        // Process the command
        switch (command) {
            case 'help':
                addOutputLine('Available commands: help, scan, connect, disconnect, ls, cd, upload, execute, learn, briefing, start_mission');
                break;
            case 'start_mission':
                if (args.length === 0) {
                    addOutputLine("Usage: start_mission <id>");
                    break;
                }
                const missionId = parseInt(args[0]);
                if (currentGameMission && currentGameMission.active) {
                    addOutputLine("A mission is already active. Complete or abort it first.");
                    break;
                }
                if (missionId === 1) {
                    currentGameMission = {
                        id: 1,
                        name: "Basic DLL Hijacking",
                        active: true,
                        targetIp: "192.168.1.101",
                        vulnerableProgram: "OldGreeter.exe",
                        vulnerablePath: normalizePath("C:\\Program Files\\OldGreeter\\"),
                        expectedDllName: "version.dll",
                        objectiveMet: false,
                        briefingDetails: "Our intel suggests OldGreeter.exe on target 192.168.1.101 loads 'version.dll' from its own directory. If you can place your own 'version.dll' there and run the program, you should gain control. Objective: Upload 'version.dll' to 'C:\\Program Files\\OldGreeter\\' and execute 'OldGreeter.exe'."
                    };
                    simulatedFileSystems[currentGameMission.targetIp] = {
                        "C:\\": { type: "dir", children: { 
                            "Program Files": { type: "dir", children: { 
                                "OldGreeter": { type: "dir", children: {
                                    "OldGreeter.exe": { type: "file", content: "Executable" },
                                    "config.ini": { type: "file", content: "Configuration" }
                                }}
                            }},
                            "Windows": { type: "dir", children: {}}, // Adding Windows dir for realism
                            "Users": { type: "dir", children: {}}    // Adding Users dir for realism
                        }}
                    };
                    if(connectedIp === currentGameMission.targetIp) {
                        currentPath = normalizePath("C:\\"); // Reset path if connected to mission target
                    }
                    addOutputLine(`Mission 1: Basic DLL Hijacking started. Target: ${currentGameMission.targetIp}. Type 'briefing' for details.`);
                } else if (missionId === 3) {
                    currentGameMission = {
                        id: 3,
                        name: "Reflective DLL Injection",
                        active: true,
                        targetIp: "192.168.1.202",
                        targetProcessName: "SecureLogger.exe",
                        targetPid: 1234, // Simulated PID
                        requiredTool: "reflective_injector.exe",
                        payloadDll: "stealth_payload.dll",
                        objectiveMet: false,
                        briefingDetails: "Intel indicates 'SecureLogger.exe' (PID " + 1234 + ") on " + "192.168.1.202" + " is vulnerable. Standard injection methods are detected. You'll need to use 'reflective_injector.exe' with 'stealth_payload.dll' to bypass its defenses. Objective: Inject 'stealth_payload.dll' into 'SecureLogger.exe' (PID " + 1234 + ") reflectively."
                    };
                    simulatedFileSystems[currentGameMission.targetIp] = { // Basic FS for this target
                        "C:\\": { type: "dir", children: { "Windows": { type: "dir", children: {} }, "ProgramData": { type: "dir", children: {} }} }
                    };
                    // No specific files needed for player to interact with on target FS for this mission directly
                    if (connectedIp === currentGameMission.targetIp) {
                        currentPath = normalizePath("C:\\"); // Reset path if connected
                    }
                    addOutputLine("Mission 3: Reflective DLL Injection started. Target: 192.168.1.202. Type 'briefing' for details.");
                }
                else {
                    addOutputLine("Invalid mission ID.");
                }
                break;
            case 'briefing':
                if (currentGameMission && currentGameMission.active) {
                    addOutputLine(currentGameMission.briefingDetails);
                    let status = "";
                    if (currentGameMission.id === 1) {
                        status = "Status: Malicious DLL not yet uploaded to the correct path.";
                        if (simulatedFileSystems[currentGameMission.targetIp] &&
                            simulatedFileSystems[currentGameMission.targetIp]["C:\\"] &&
                            simulatedFileSystems[currentGameMission.targetIp]["C:\\"].children["Program Files"] &&
                            simulatedFileSystems[currentGameMission.targetIp]["C:\\"].children["Program Files"].children["OldGreeter"] &&
                            simulatedFileSystems[currentGameMission.targetIp]["C:\\"].children["Program Files"].children["OldGreeter"].children[currentGameMission.expectedDllName]) {
                            status = "Status: Malicious DLL seems to be in place.";
                        }
                        if (currentGameMission.objectiveMet) {
                            status = "Status: Objective Accomplished!";
                        }
                    } else if (currentGameMission.id === 3) {
                        if (currentGameMission.objectiveMet) {
                            status = "\nStatus: Objective Accomplished! SecureLogger.exe has been compromised.";
                        } else {
                            status = "\nStatus: Awaiting reflective injection of " + currentGameMission.payloadDll + " into " + currentGameMission.targetProcessName + " (PID " + currentGameMission.targetPid + ").";
                        }
                    }
                    addOutputLine(status);
                } else {
                    addOutputLine("No mission active. Type 'start_mission <id>' to begin.");
                }
                break;
            case 'scan':
                if (args.length === 0) {
                    addOutputLine("Usage: scan <ip_address>");
                } else {
                    const scanIp = args[0];
                    addOutputLine(`Scanning ${scanIp}...`);
                    if (currentGameMission && scanIp === currentGameMission.targetIp && currentGameMission.id === 1) {
                        addOutputLine(`Open ports: 80 (HTTP), 443 (HTTPS), 22 (SSH)`);
                        addOutputLine(`Services: \n  - ${currentGameMission.vulnerableProgram} running`);
                    } else if (scanIp === "192.168.1.202") { // Target IP for Mission 3
                         addOutputLine(`Open ports: 443 (HTTPS), 9001 (Custom/SecureLogger)`);
                         addOutputLine("Running Processes:\n  PID  Name\n  ---- ----\n  1234 SecureLogger.exe\n  789  explorer.exe\n  800  svchost.exe");
                    }
                     else {
                       addOutputLine(`Open ports: 80 (HTTP), 445 (SMB), 3389 (RDP)`);
                    }
                }
                break;
            case 'connect':
                if (args.length === 0) {
                    addOutputLine("Usage: connect <ip_address>");
                } else if (connectedIp) {
                    addOutputLine(`Already connected to ${connectedIp}. Disconnect first.`);
                } else {
                    const targetIpToConnect = args[0];
                    connectedIp = targetIpToConnect;
                    currentPath = normalizePath("C:\\"); // Set to root on connect
                    addOutputLine(`Connected to ${connectedIp}. Current path: ${currentPath}`);
                    // If target IP does not have a simulated FS, create a basic one
                    if (!simulatedFileSystems[connectedIp]) {
                        simulatedFileSystems[connectedIp] = {
                            "C:\\": { type: "dir", children: {
                                "Windows": { type: "dir", children: {}},
                                "Users": { type: "dir", children: {}}
                            }}
                        };
                         addOutputLine(`Basic file system initialized for ${connectedIp}.`);
                    }
                }
                break;
            case 'disconnect':
                if (connectedIp) {
                    addOutputLine(`Disconnected from ${connectedIp}.`);
                    connectedIp = null;
                    currentPath = null; // Reset current path
                } else {
                    addOutputLine("Not currently connected.");
                }
                break;
            case 'ls':
                if (!connectedIp || !currentPath) {
                    addOutputLine("Not connected to any target or path not set.");
                } else {
                    const pathObj = getPathObject(connectedIp, currentPath);
                    if (pathObj) {
                        const items = Object.keys(pathObj);
                        if (items.length === 0) {
                            addOutputLine("Directory is empty.");
                        } else {
                            items.forEach(item => {
                                const itemType = pathObj[item].type === "dir" ? "<DIR>" : "<FILE>";
                                addOutputLine(`${itemType}  ${item}`);
                            });
                        }
                        // Mission 1 specific: list hacked.txt if objective met
                        if (currentGameMission && currentGameMission.active && currentGameMission.id === 1 && currentGameMission.objectiveMet &&
                            connectedIp === currentGameMission.targetIp &&
                            normalizePath(currentPath) === currentGameMission.vulnerablePath) {
                            addOutputLine("<FILE>  hacked.txt");
                        }
                    } else {
                        addOutputLine(`Error: Path ${currentPath} not found on ${connectedIp}.`);
                    }
                }
                break;
            case 'cd':
                if (!connectedIp || !currentPath) {
                    addOutputLine("Not connected to any target or path not set.");
                } else if (args.length === 0) {
                    addOutputLine("Usage: cd <directory>");
                } else {
                    const targetDir = args[0];
                    let newPath;

                    if (targetDir === "..") {
                        // Go up one level
                        const pathParts = normalizePath(currentPath).split('\\').filter(p => p);
                        if (pathParts.length > 1) { // Can't go above C:\
                            pathParts.pop();
                            newPath = normalizePath(pathParts.join('\\') + '\\');
                            if (pathParts.length === 1 && pathParts[0].toUpperCase() === "C:") {
                                newPath = "C:\\"; // Ensure it becomes C:\
                            }
                        } else {
                            newPath = currentPath; // Already at root
                        }
                    } else {
                        // Go to a subdirectory
                        let tempPath = normalizePath(currentPath);
                        if (!tempPath.endsWith('\\')) tempPath += '\\';
                        newPath = normalizePath(tempPath + targetDir);
                    }
                    
                    // Validate new path
                    const pathObj = getPathObject(connectedIp, newPath);
                    if (pathObj) { // Check if path resolves to a directory's children or a file
                         // We need to ensure what getPathObject returns is a directory's children list
                         // For cd, we need to check if newPath points to a directory itself.
                         // A bit of a hack: try to get one level deeper to see if it's a dir
                         let checkDir = simulatedFileSystems[connectedIp];
                         const newPathParts = newPath.split('\\').filter(p=>p);
                         let validDir = true;
                         for(let i=0; i<newPathParts.length; i++){
                             const part = newPathParts[i];
                             if(checkDir && checkDir[part] && checkDir[part].type === 'dir'){
                                 if(i === newPathParts.length -1) { // target directory itself
                                    checkDir = checkDir[part]; // Move into the target directory to check its type
                                    break; 
                                 }
                                 checkDir = checkDir[part].children;
                             } else if (part.toUpperCase() === "C:" && i===0 && checkDir["C:\\"]) { // Handling C:\ root
                                checkDir = checkDir["C:\\"];
                                if(newPathParts.length === 1) break; // if only C:
                                checkDir = checkDir.children;
                             } else {
                                 validDir = false;
                                 break;
                             }
                         }

                        if (validDir && checkDir && checkDir.type === 'dir') {
                            currentPath = newPath;
                            addOutputLine(`Current path: ${currentPath}`);
                        } else {
                            addOutputLine(`Directory not found: ${targetDir}`);
                        }
                    } else {
                        addOutputLine(`Directory not found: ${targetDir}`);
                    }
                }
                break;
            case 'upload':
                if (!connectedIp) {
                    addOutputLine("Not connected to any target.");
                } else if (args.length < 2) {
                    addOutputLine("Usage: upload <local_file> <remote_path>");
                } else {
                    const localFile = args[0];
                    const remotePathArg = args.join(' ').substring(args[0].length + 1).trim(); // Handle spaces in path
                    const normalizedRemotePath = normalizePath(remotePathArg);
                    
                    if (currentGameMission && currentGameMission.active && currentGameMission.id === 1 &&
                        connectedIp === currentGameMission.targetIp &&
                        localFile === currentGameMission.expectedDllName &&
                        normalizedRemotePath === currentGameMission.vulnerablePath) {
                        
                        // Get the parent directory object to add the file
                        const parentPathParts = currentGameMission.vulnerablePath.split('\\').filter(p => p);
                        parentPathParts.pop(); // Remove the last part (OldGreeter) to get to "Program Files"
                        let parentDirObj = simulatedFileSystems[connectedIp];
                        parentPathParts.forEach(part => {
                            if(parentDirObj && parentDirObj[part] && parentDirObj[part].type === 'dir'){
                                parentDirObj = parentDirObj[part].children;
                            } else if (part.toUpperCase() === "C:" && parentDirObj["C:\\"]){
                                parentDirObj = parentDirObj["C:\\"].children;
                            } else {
                                parentDirObj = null; // Path error
                            }
                        });
                        const targetDirName = currentGameMission.vulnerablePath.split('\\').filter(p => p).pop();


                        if (parentDirObj && parentDirObj[targetDirName] && parentDirObj[targetDirName].type === 'dir') {
                            parentDirObj[targetDirName].children[currentGameMission.expectedDllName] = { type: "file", content: "Malicious DLL" };
                            addOutputLine(`${currentGameMission.expectedDllName} uploaded to ${normalizedRemotePath} on ${connectedIp}.`);
                        } else {
                            addOutputLine(`Upload failed. Target directory ${normalizedRemotePath} not found or is not a directory.`);
                        }
                    } else {
                        addOutputLine(`Simulating upload of ${localFile} to ${normalizedRemotePath}... Upload complete.`);
                        // Generic upload to any path (if needed, for non-mission tasks)
                        // For now, we'll just simulate it without modifying the FS unless it's for the mission
                    }
                }
                break;
            case 'execute':
                const programName = args[0] ? args[0].toLowerCase() : "";
                // Mission 3: Reflective DLL Injection
                if (programName === "reflective_injector.exe") {
                    if (!currentGameMission || !currentGameMission.active || currentGameMission.id !== 3) {
                        addOutputLine("No active mission requires reflective_injector.exe.");
                        break;
                    }
                    if (args.length < 2) {
                        addOutputLine("Usage: execute reflective_injector.exe <pid> <dll_name>");
                        break;
                    }
                    const pidArg = parseInt(args[1]); // Args are program_name, pid, dll_name
                    const dllNameArg = args[2];

                    if (pidArg === currentGameMission.targetPid && dllNameArg && dllNameArg.toLowerCase() === currentGameMission.payloadDll.toLowerCase()) {
                        currentGameMission.objectiveMet = true;
                        addOutputLine(`Executing reflective_injector.exe... Payload ${currentGameMission.payloadDll} injected into PID ${currentGameMission.targetPid} successfully! A brief flicker on the (simulated) SecureLogger console indicates activity. Mission Accomplished!`);
                    } else {
                        addOutputLine("Reflective injector failed: Incorrect PID, DLL name for current objective, or target process not found.");
                    }
                } 
                // Mission 1: Basic DLL Hijacking & Generic execution
                else if (!connectedIp || !currentPath) {
                    addOutputLine("Not connected to any target or path not set.");
                } else if (args.length === 0 && !programName) { // Check if programName is empty
                    addOutputLine("Usage: execute <program_name> [args]");
                } else {
                    if (currentGameMission && currentGameMission.active && currentGameMission.id === 1 &&
                        connectedIp === currentGameMission.targetIp &&
                        programName === currentGameMission.vulnerableProgram.toLowerCase() && // programName is already lowercased
                        normalizePath(currentPath) === currentGameMission.vulnerablePath) {

                        // Check if the vulnerable DLL is in place
                        const dllPathObj = getPathObject(connectedIp, currentGameMission.vulnerablePath);
                        if (dllPathObj && dllPathObj[currentGameMission.expectedDllName] && dllPathObj[currentGameMission.expectedDllName].type === 'file') {
                            currentGameMission.objectiveMet = true;
                            // Add "hacked.txt" to the vulnerable path's directory content
                            if(simulatedFileSystems[connectedIp] && getPathObject(connectedIp, currentGameMission.vulnerablePath)){
                                 // Need to access the children of the vulnerablePath directly
                                let targetDirChildren = simulatedFileSystems[connectedIp];
                                const pathParts = currentGameMission.vulnerablePath.split('\\').filter(p=>p);
                                pathParts.forEach(part => {
                                    if(targetDirChildren && targetDirChildren[part] && targetDirChildren[part].type === 'dir') {
                                        targetDirChildren = targetDirChildren[part].children;
                                    } else if (part.toUpperCase() === "C:" && targetDirChildren["C:\\"]) {
                                        targetDirChildren = targetDirChildren["C:\\"].children;
                                    }
                                });
                                if (targetDirChildren) {
                                     targetDirChildren["hacked.txt"] = { type: "file", content: "Proof of hack" };
                                }
                            }
                            addOutputLine(`Executing ${currentGameMission.vulnerableProgram}... The program stutters, and a new file 'hacked.txt' suddenly appears in ${currentGameMission.vulnerablePath}! Mission Accomplished!`);
                        } else {
                            addOutputLine(`Executing ${currentGameMission.vulnerableProgram}... The program runs as expected. Nothing unusual happens.`);
                        }
                    } else {
                        addOutputLine(`Simulating execution of ${programName}...`);
                    }
                }
                break;
            case 'learn':
                if (args.length === 0) {
                    addOutputLine(`Usage: learn <topic_name>. Available topics: ${Object.keys(educationalContent).join(", ")}.`);
                } else {
                    const topic = args.join(' ').toLowerCase();
                    const content = educationalContent[topic];
                    if (content) {
                        let outputText = `--- ${content.title} ---\n\n`;
                        outputText += `What it is: ${content.what_it_is}\n\n`;
                        outputText += `How it works: ${content.how_it_works}\n\n`;
                        outputText += `Real-world Tools: ${content.real_world_tools}\n\n`;
                        outputText += `Prevention & Detection:\n`;
                        content.prevention_detection.forEach(point => {
                            outputText += `- ${point}\n`;
                        });
                        addOutputLine(outputText);
                    } else {
                        addOutputLine(`No educational content found for "${topic}". Available topics: ${Object.keys(educationalContent).join(", ")}.`);
                    }
                }
                break;
            default:
                addOutputLine(`Command not found: ${command}. Type 'help' for a list of commands.`);
        }
    }

    commandInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            const commandText = commandInput.value.trim();

            // 1. Create a new line for the historical command
            const historyLine = document.createElement('div');
            historyLine.className = 'input-line'; // Use the same class for styling

            const promptSpan = document.createElement('span');
            promptSpan.className = 'prompt';
            // Get current prompt text from the visible input line.
            // This assumes the prompt span in inputLine is always up-to-date.
            promptSpan.textContent = inputLine.querySelector('.prompt').textContent; 

            const commandTextSpan = document.createElement('span');
            commandTextSpan.textContent = commandText;
            // commandTextSpan.style.color = '#0f0'; // Already handled by #commandInput styles, and this is history

            historyLine.appendChild(promptSpan);
            historyLine.appendChild(commandTextSpan);
            output.appendChild(historyLine);

            // 2. Process the command
            if (commandText) { // Only process if there's a command
                handleCommand(commandText);
            }

            // 3. Clear the input field
            commandInput.value = '';

            // 4. Auto-scroll
            terminal.scrollTop = terminal.scrollHeight;

            // 5. Ensure focus 
            commandInput.focus();
        }
    });

    terminal.addEventListener('click', function(event) {
        // Only focus if the click is not on the input itself or within something interactive in output
        // and also not on elements within the static input-line like the prompt itself.
        if (event.target === terminal || event.target === output ) {
            commandInput.focus();
        }
    });

    // Initial focus
    commandInput.focus();
});
