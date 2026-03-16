def main():
    # Start FastAPI app if run directly. This requires uvicorn to be installed.
    try:
        import uvicorn
        from osforensics.api import app

        uvicorn.run(app, host="127.0.0.1", port=8000)
    except Exception:
        # Fallback behavior when running without dependencies: simple message
        print("OS Forensics prototype. Install dependencies and run as a FastAPI server.")


if __name__ == "__main__":
    main()
