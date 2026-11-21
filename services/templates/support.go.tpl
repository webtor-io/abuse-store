{{ if .AnyExempt }}EXEMPT: an infohash marked exempt below was reviewed and exempted; the report was NOT added to the stoplist for it.

{{ end }}{{ .Abuse.Description }}

Notice ID: {{ .Abuse.NoticeID }}
{{ range .Hashes }}Infohash:  {{ .Infohash }}{{ if .Exempt }} (exempt){{ else if .Existed }} (already in the stoplist){{ end }}
{{ end }}Filename:  {{ .Abuse.Filename }}
Work:      {{ .Abuse.Work }}
Cause:     {{ .Abuse.Cause | CauseName }}
Email:     {{ .Abuse.Email }}
{{ if IsIllegal .Abuse }}{{ if and .PurgeNow (not .AllExempt) }}
Data purge: immediate, sent with this notice.
{{ else if .Added }}
Data purge: scheduled for {{ .Abuse.PurgeAfter.UTC.Format "2006-01-02 15:04 UTC" }}. The block is already in place.
Setting exempt on the row or deleting it before then keeps the data:
  UPDATE abuse SET exempt = true WHERE infohash = '<hash>';
An infohash already in the stoplist keeps the schedule of its earlier notice.
{{ end }}{{ end }}
