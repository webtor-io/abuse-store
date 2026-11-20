{{ if .Abuse.Exempt }}EXEMPT: this infohash was reviewed and exempted; the report was NOT added to the stoplist.

{{ end }}{{ .Abuse.Description }}

Notice ID: {{ .Abuse.NoticeID }}
Infohash:  {{ .Abuse.Infohash }}
Filename:  {{ .Abuse.Filename }}
Work:      {{ .Abuse.Work }}
Cause:     {{ .Abuse.Cause | CauseName }}
Email:     {{ .Abuse.Email }}
