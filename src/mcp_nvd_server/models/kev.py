from pydantic import BaseModel, Field

class CisaKevMetadata(BaseModel):
  exploit_add_date: str | None = None
  action_due_date: str | None = None
  required_action: str | None = None
  vulnerability_name: str | None = None
  known_ransomware_campaign_use: str | None = None
  notes: str | None = None
  kev_cwes: list[str] = Field(default_factory=list)
  in_kev: bool = False

class KEVRecord(BaseModel):
  cve_id: str

  
  known_ransomware_campaign_use: str | None = None
  notes: str | None = None
  kev_cwes: list[str] = Field(default_factory=list)
  #overlap fields
  vendor_product: str | None = None
  product: str | None = None
  vulnerability_name: str | None = None
  date_added: str | None = None
  required_action: str | None = None
  due_date: str | None = None

class KEVLookupResult(BaseModel):
  found: bool
  kev: KEVRecord | None = None
