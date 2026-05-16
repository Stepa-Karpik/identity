from uuid import uuid4
from fastapi import FastAPI, status
from pydantic import BaseModel

app = FastAPI(title="identity")
subjects: dict[str, str] = {}
sessions: dict[str, str] = {}

class SubjectCreate(BaseModel):
    email: str
class SessionCreate(BaseModel):
    subject_id: str

@app.get('/healthz')
def healthz(): return {'status': 'ok', 'service': 'identity'}
@app.post('/api/v1/subjects', status_code=status.HTTP_201_CREATED)
def create_subject(payload: SubjectCreate):
    subject_id = f'usr_{uuid4().hex}'
    subjects[subject_id] = payload.email
    return {'subject_id': subject_id, 'email': payload.email}
@app.post('/api/v1/sessions', status_code=status.HTTP_201_CREATED)
def create_session(payload: SessionCreate):
    session_id = f'sess_{uuid4().hex}'
    sessions[session_id] = payload.subject_id
    return {'session_id': session_id, 'subject_id': payload.subject_id}
