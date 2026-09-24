# Running the approved incident workspace

From the project folder, double-click **Start Workspace.cmd**, or run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/start-workspace.ps1
```

Open **http://127.0.0.1:8768**. Keep the terminal running; Ctrl+C stops the server. Choose another port with `-Port 8770` if necessary.

The launcher uses the existing `.venv` and existing dependencies. If `ANTHROPIC_API_KEY` is not already in the process environment, it reads that key alone from the project's `.env` file without printing it. The credential stays server-side. There are no external browser scripts, fonts or analytics.

You can also run `python app/workspace_server.py` directly; in that case set the credential in the environment yourself. The legacy `streamlit run app/main.py` still opens the old interface.

## How the interface works

- **Brief:** saved investigation counts, expandable findings and uncertainty; start a conversation or follow the timeline.
- **Timeline:** all current findings, sorted by recorded time; movement and data filters, technique names/IDs and source links.
- **Systems & accounts:** entities named by the pipeline, their supporting records, and other observed systems. Involvement is not automatically labelled compromise.
- **Evidence:** search all ingested records and open the original fields/JSON.
- **How it works:** real saved stage reports, verification output, build provenance and answer availability.
- **Assistant:** calls the existing model-backed answer function and preserves its citation gate. Sources open in the same inspector; Back to conversation returns to your answer. Individual claims can be expanded to inspect their supporting events.

The answer may take time because it uses the configured backend model and may perform a bounded repair after a failed citation check. One model request is processed at a time. A disconnected request may finish server-side; avoid resubmitting until it completes. Browser reload clears conversation history; it is not stored in browser storage or the application server.

## If chat is unavailable

- **Credential missing:** set `ANTHROPIC_API_KEY` or configure `.env`, then restart the launcher.
- **Build contract changed:** finish the backend work and rebuild using the repository's documented build command, then refresh the workspace. The UI deliberately does not rewrite investigation artifacts.
- **Build changing / files missing:** wait for the build to finish and use Refresh investigation.
- **Answer withheld:** review the displayed reason. The frontend never replaces a failed backend response with a canned answer.

## Evidence and limitations

Displayed narratives reflect the saved engine outputs and may expose backend analysis errors. The frontend does not hide weak findings to reproduce the design preview. Source resolution, structural citation checks and saved verification reports are not proof that a model's interpretation is semantically correct.

Export brief downloads the saved findings and their source details. This is an analyst review document, not an approved board report. No containment action is executed by the interface.

After backend code changes, restart the workspace server as well as refreshing the browser. Python modules are loaded at server startup.


Graph review: the workspace answer adapter now includes every saved timeline finding and scope entity, the full gap ledger, and explicitly requested source records with existing observation IDs. The backend citation gate is unchanged. How it works reports graph-reference integrity; this is a structural check, not semantic validation. Scope labels distinguish named entities from supporting-record neighbours. Copy answer retains limitations and source details.

