"""Chat & Agent rotaları."""
from __future__ import annotations
import uuid, time, json, asyncio
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from fetih_api.models.schemas import (
    ChatRequest, ChatResponse, ToolCall, UsageInfo,
    BackgroundTaskResponse,
)
from fetih_api.routes.deps import get_or_create_agent, submit_background_task, get_task_status

router = APIRouter()


def _build_response(agent_result: dict, session_id: str, model: str, provider: str,
                    start_time: float) -> ChatResponse:
    """Agent sonucunu ChatResponse'a dönüştür."""
    duration = (time.time() - start_time) * 1000
    tc_list = []
    for tc in agent_result.get("tool_calls", []) or []:
        tc_list.append(ToolCall(
            name=tc.get("name", "unknown"),
            call_id=tc.get("id", ""),
            args=tc.get("args", {}),
            result=str(tc.get("result", ""))[:500] if tc.get("result") else None,
        ))

    usage_raw = agent_result.get("usage", {}) or {}
    return ChatResponse(
        id=f"msg_{uuid.uuid4().hex[:8]}",
        session_id=session_id,
        model=model,
        provider=provider,
        response=agent_result.get("final_response", agent_result.get("response", "")),
        tool_calls=tc_list,
        tool_call_count=len(tc_list),
        iteration_count=agent_result.get("iterations", 0),
        usage=UsageInfo(
            input_tokens=usage_raw.get("input_tokens", 0),
            output_tokens=usage_raw.get("output_tokens", 0),
            cache_read_tokens=usage_raw.get("cache_read_input_tokens", 0),
            cache_write_tokens=usage_raw.get("cache_creation_input_tokens", 0),
        ),
        duration_ms=round(duration, 1),
        stopped_by=agent_result.get("stop_reason", "agent"),
    )


@router.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    """Prompt gönder, tam yanıt al (tool call'larla birlikte)."""
    session_id = req.session_id or f"sess_{uuid.uuid4().hex[:8]}"
    agent = get_or_create_agent(
        model=req.model, provider=req.provider,
        api_key=req.api_key, base_url=req.base_url,
        max_iterations=req.max_iterations, session_id=session_id,
    )
    start = time.time()
    try:
        result = agent.run_conversation(req.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")

    return _build_response(result, session_id, agent.model or "unknown",
                           getattr(agent, 'provider', 'unknown'), start)


@router.post("/chat/stream")
async def chat_stream(req: ChatRequest):
    """SSE streaming sohbet."""
    session_id = req.session_id or f"sess_{uuid.uuid4().hex[:8]}"
    agent = get_or_create_agent(
        model=req.model, provider=req.provider,
        api_key=req.api_key, base_url=req.base_url,
        max_iterations=req.max_iterations, session_id=session_id,
    )

    async def event_stream():
        buffer = []
        start = time.time()

        def on_delta(text: str):
            buffer.append(text)
            return f"data: {json.dumps({'type': 'delta', 'text': text})}\n\n"

        try:
            # Non-streaming fallback (streaming callback'larla)
            result = agent.run_conversation(req.message)
            full_text = result.get("final_response", "")
            # Chunk'la
            chunk_size = 20
            for i in range(0, len(full_text), chunk_size):
                chunk = full_text[i:i+chunk_size]
                yield f"data: {json.dumps({'type': 'delta', 'text': chunk})}\n\n"
                await asyncio.sleep(0.01)

            # Tool call'ları bildir
            for tc in (result.get("tool_calls", []) or []):
                yield f"data: {json.dumps({'type': 'tool_call', 'name': tc.get('name', ''), 'args': tc.get('args', {})})}\n\n"

            usage = result.get("usage", {}) or {}
            yield f"data: {json.dumps({'type': 'done', 'session_id': session_id, 'usage': usage, 'duration_ms': round((time.time()-start)*1000,1)})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/chat/background", response_model=BackgroundTaskResponse)
async def chat_background(req: ChatRequest):
    """Prompt'u arkaplanda çalıştır."""
    task_id = f"task_{uuid.uuid4().hex[:8]}"
    session_id = req.session_id or f"sess_{uuid.uuid4().hex[:8]}"
    agent = get_or_create_agent(
        model=req.model, provider=req.provider,
        api_key=req.api_key, base_url=req.base_url,
        max_iterations=req.max_iterations, session_id=session_id,
    )
    submit_background_task(task_id, agent.run_conversation, req.message)
    return BackgroundTaskResponse(task_id=task_id, status="queued")


@router.get("/chat/tasks", response_model=list[BackgroundTaskResponse])
async def list_tasks():
    """Tüm arkaplan görevlerini listele."""
    result = []
    for tid, task in get_task_status.__self__().items() if hasattr(get_task_status, '__self__') else {}:
        result.append(BackgroundTaskResponse(task_id=tid, status=task.get("status", "unknown")))
    return result or []


@router.get("/chat/tasks/{task_id}", response_model=BackgroundTaskResponse)
async def get_task(task_id: str):
    """Belirli arkaplan görevinin durumu."""
    from fetih_api.routes.deps import _active_tasks
    task = _active_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    return BackgroundTaskResponse(
        task_id=task_id,
        status=task.get("status", "unknown"),
        progress=task.get("progress"),
        error=task.get("error"),
    )


@router.delete("/chat/tasks/{task_id}")
async def cancel_task(task_id: str):
    """Arkaplan görevini iptal et."""
    from fetih_api.routes.deps import _active_tasks
    if task_id not in _active_tasks:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    _active_tasks[task_id]["status"] = "cancelled"
    return {"status": "cancelled", "task_id": task_id}
