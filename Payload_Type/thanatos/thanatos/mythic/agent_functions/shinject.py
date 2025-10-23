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
            file_resp = await MythicRPC().execute(
                "get_file", 
                task_id=taskData.Task.ID,
                file_id=taskData.args.get_arg("shellcode"),
                get_contents=False
            )
            
            if file_resp.status == MythicStatus.Success:
                original_file_name = file_resp.response[0]["filename"]
                
                if len(file_resp.response) > 0:
                    response.DisplayParams = "Injecting {} into PID {}".format(
                        original_file_name, 
                        taskData.args.get_arg("process_id")
                    )
                else:
                    raise Exception("Failed to find the named file. Have you uploaded it before? Did it get deleted?")
            
            # Mark the file for deletion after the agent fetches it
            # This should automatically download the file to the agent
            await MythicRPC().execute("update_file",
                file_id=taskData.args.get_arg("shellcode"),
                delete_after_fetch=True,
                comment="Uploaded into memory for shinject"
            )
            
            # Debug: Log the file information
            print(f"DEBUG: File {original_file_name} (ID: {taskData.args.get_arg('shellcode')}) marked for download to agent")
            
        except Exception as e:
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