from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class ClipboardArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ClipboardCommand(CommandBase):
    cmd = "clipboard"
    needs_admin = False
    help_cmd = "clipboard"
    description = "Retrieve the contents of the clipboard"
    version = 1
    author = "@checkymander"
    argument_class = ClipboardArguments
    attackmapping = []
    browser_script = None
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        try:
            # The response should be the clipboard content directly
            if response and response.strip():
                resp.UserOutput = f"Clipboard contents:\n{response}"
            else:
                resp.UserOutput = "Clipboard is empty or contains no text data."
                
        except Exception as e:
            resp.UserOutput = f"Error processing clipboard response: {e}"
            resp.Success = False
            
        return resp
