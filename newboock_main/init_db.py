from database import Base, engine, DATABASE_URL


def main() -> None:
    print(f"Initializing database at: {DATABASE_URL}")
    Base.metadata.create_all(bind=engine)
    print("Done.")


if __name__ == "__main__":
    main()
