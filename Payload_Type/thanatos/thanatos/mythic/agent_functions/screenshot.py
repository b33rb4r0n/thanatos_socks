from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json

class ScreenshotArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ScreenshotCommand(CommandBase):
    cmd = "screenshot"
    needs_admin = False
    help_cmd = "screenshot"
    description = "Take a screenshot of the current desktop."
    version = 1
    author = "@checkymander"
    argument_class = ScreenshotArguments
    browser_script = BrowserScript(script_name="screenshot", author="@checkymander", for_new_ui=True)
    attackmapping = ["T1113"]  # Screen Capture
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows]  # Windows only for this implementation
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "Taking screenshot of desktop"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        """
        Process the agent response from screenshot command
        """
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        try:
            if response:
                response_text = str(response)
                
                # With the Apollo-style implementation, the agent handles file upload via RPC
                # We just need to process the success/failure response
                if "success" in response_text.lower() or "captured" in response_text.lower():
                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=response_text.encode()
                    ))
                    
                    # Also update the task output in the database
                    await SendMythicRPCResponseUpdate(MythicRPCResponseUpdateMessage(
                        TaskID=task.Task.ID,
                        Response=response_text
                    ))
                    
                    # Log successful capture
                    await SendMythicRPCOperationEventLogCreate(MythicRPCOperationEventLogCreateMessage(
                        TaskID=task.Task.ID,
                        Message="Screenshot captured successfully",
                        Level="info"
                    ))
                else:
                    # Error response
                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=response_text.encode()
                    ))
            else:
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response="No response received from agent".encode()
                ))
                
        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing screenshot response: {str(e)}".encode()
            ))
            resp.Success = False
            resp.Error = str(e)
            
        return resp