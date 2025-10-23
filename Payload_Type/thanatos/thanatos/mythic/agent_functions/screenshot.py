from mythic_container.MythicCommandBase import *
from uuid import uuid4
import json
from os import path
from mythic_container.MythicRPC import *
import base64

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
    version = 2
    author = "@reznok, @djhohnstein"
    argument_class = ScreenshotArguments
    browser_script = BrowserScript(script_name="screenshot", author="@djhohnstein", for_new_ui=True)
    attackmapping = ["T1113"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        """
        Process the agent response from screenshot command
        """
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        try:
            if response:
                response_text = str(response)
                
                # The agent returns a file path, we need to create a download task for it
                if "To download to Mythic, use:" in response_text:
                    # Extract the file path from the response
                    lines = response_text.split('\n')
                    file_path = None
                    for line in lines:
                        if line.strip().startswith('download '):
                            file_path = line.strip().replace('download ', '')
                            break
                    
                    if file_path:
                        # Create a download task for the screenshot
                        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                            TaskID=task.Task.ID,
                            Response=f"Screenshot saved to: {file_path}\n\nTo view the screenshot, use the download command:\ndownload {file_path}".encode()
                        ))
                    else:
                        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                            TaskID=task.Task.ID,
                            Response=response_text.encode()
                        ))
                else:
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
