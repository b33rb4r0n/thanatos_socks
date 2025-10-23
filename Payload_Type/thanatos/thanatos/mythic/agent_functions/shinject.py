from mythic_container.MythicRPC import *
from mythic_container.MythicCommandBase import *
import json
import sys

class ShinjectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="shellcode", 
                type=ParameterType.File, 
                description="Shellcode to inject"
            ),
            CommandParameter(
                name="process_id",
                type=ParameterType.Number,
                description="ID of process to inject into",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                raise ValueError("Missing JSON arguments")
        else:
            raise ValueError("Missing arguments")


class ShinjectCommand(CommandBase):
    cmd = "shinject"
    needs_admin = False
    help_cmd = "shinject"
    description = "Inject shellcode from local file into target process"
    version = 1
    supported_ui_features = ["process_browser:inject"]
    author = "@B4r0n"
    attackmapping = ["T1055"]  # Process Injection

    argument_class = ShinjectArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows]  # Windows only for this implementation
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        try:
            file_id = taskData.args.get_arg("shellcode")
            print(f"DEBUG: Looking for file with ID: {file_id}")
            
            file_resp = await MythicRPC().execute(
                "get_file", 
                task_id=taskData.Task.ID,
                file_id=file_id,
                get_contents=False
            )
            
            print(f"DEBUG: File response status: {file_resp.status}")
            print(f"DEBUG: File response: {file_resp}")
            
            if file_resp.status == MythicStatus.Success:
                if len(file_resp.response) > 0:
                    original_file_name = file_resp.response[0]["filename"]
                    response.DisplayParams = "Injecting {} into PID {}".format(
                        original_file_name, 
                        taskData.args.get_arg("process_id")
                    )
                    print(f"DEBUG: Found file: {original_file_name}")
                else:
                    raise Exception("Failed to find the named file. Have you uploaded it before? Did it get deleted?")
            else:
                raise Exception(f"Failed to get file information: {file_resp.error}")
            
            # Mark the file for deletion after the agent fetches it
            # This should automatically download the file to the agent
            print(f"DEBUG: Setting delete_after_fetch=True for file {file_id}")
            update_resp = await MythicRPC().execute("update_file",
                file_id=file_id,
                delete_after_fetch=True,
                comment="Uploaded into memory for shinject"
            )
            
            print(f"DEBUG: Update file response: {update_resp}")
            print(f"DEBUG: File {original_file_name} (ID: {file_id}) marked for download to agent")
            
        except Exception as e:
            print(f"DEBUG: Error in create_go_tasking: {str(e)}")
            response.Success = False
            response.Error = f"Error preparing shellcode file: {str(e)}"
            
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        """
        Process the agent response from shellcode injection
        """
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        try:
            if response:
                response_text = str(response)
                
                # Create a task response output
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=response_text.encode()
                ))
                
                # Also update the task output in the database
                await SendMythicRPCResponseUpdate(MythicRPCResponseUpdateMessage(
                    TaskID=task.Task.ID,
                    Response=response_text
                ))
                
                # Log successful injection
                if "successfully" in response_text.lower():
                    await SendMythicRPCOperationEventLogCreate(MythicRPCOperationEventLogCreateMessage(
                        TaskID=task.Task.ID,
                        Message=f"Successfully injected shellcode into PID {task.args.get_arg('process_id')}",
                        Level="info"
                    ))
            else:
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response="No response received from agent".encode()
                ))
                
        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing shinject response: {str(e)}".encode()
            ))
            resp.Success = False
            resp.Error = str(e)
            
        return resp