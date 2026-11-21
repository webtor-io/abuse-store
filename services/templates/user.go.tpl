Hi!

{{ if .AllExempt }}
Thank you for your request! It has been received and is under moderation.
{{ else if .Abuse | IsIllegal }}
The torrents listed below have been added to stoplist and will become unavailable for users in an hour.
All connected cached content will be purged as well.
{{ else }}
Thank you for your request! We will do our best to solve it!
{{ end }}

Notice ID: {{ .Abuse.NoticeID }}
{{ range .Hashes }}Infohash:  {{ .Infohash }}{{ if .Exempt }} (under moderation){{ end }}
{{ end }}Filename:  {{ .Abuse.Filename }}
Description:

{{ .Abuse.Description | EmailQuote }}

This message was generated automatically.

If you have any additional question please email directly to {{ .Support }}

Sincerely yours, Webtor Support Team.