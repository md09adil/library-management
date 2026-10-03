const express = require("express");
const { Pool } = require("pg");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 4
    }
}));
// AUTHENTICATION MIDDLEWARE

function requireAuth(req, res, next) {

    if (req.session.user) {
        return next();
    }

    // API requests should receive JSON
    if (req.path.startsWith("/api/")) {
        return res.status(401).json({
            message: "Please login first."
        });
    }

    // Other protected pages go to login
    return res.redirect("/");
}

const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
});

// Serve files from public folder
// Protect HTML pages
app.use((req, res, next) => {

    if (
        req.path.startsWith("/pages/") &&
        !req.path.endsWith("/login.html")
    ) {
        return requireAuth(req, res, next);
    }

    next();
});
app.use(express.static(path.join(__dirname, "public")));
// Protect all API routes
app.use("/api", requireAuth);
// Home page
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "pages", "login.html"));
});
app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "pages", "dashboard.html"));
    
});
app.get("/reports", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "pages", "reports.html"));
});
// Login
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query(
            "SELECT * FROM users WHERE username = $1",
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }

        const user = result.rows[0];

        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }

        req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role
        };

        res.json({
            success: true,
            message: "Login successful"
        });

    } catch (error) {
        console.error("Login error:", error);

        res.status(500).json({
            message: "Server error"
        });
    }
});
// ==================== BOOK APIs ====================

// Get all books
app.get("/api/books", async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                books.*,
                categories.name AS category_name
            FROM books
            LEFT JOIN categories
                ON books.category_id = categories.id
            ORDER BY books.id DESC
        `);

        res.json(result.rows);
    } catch (error) {
        console.error("Get books error:", error);
        res.status(500).json({
            message: "Unable to load books"
        });
    }
});


// Add a new book
app.post("/api/books", async (req, res) => {
    const {
        title,
        author,
        isbn,
        publisher,
        total_copies,
        category_id
    } = req.body;

    if (!title || !author || !total_copies) {
        return res.status(400).json({
            message: "Title, author and total copies are required"
        });
    }

    try {
        const result = await pool.query(
            `
            INSERT INTO books
            (
                title,
                author,
                isbn,
                category_id,
                publisher,
                total_copies,
                available_copies
            )
            VALUES ($1, $2, $3, $4, $5, $6, $6)
            RETURNING *
            `,
            [
                title,
                author,
                isbn || null,
                category_id || null,
                publisher || null,
                total_copies
            ]
        );

        res.status(201).json(result.rows[0]);

    } catch (error) {
        console.error("Add book error:", error);

        if (error.code === "23505") {
            return res.status(400).json({
                message: "A book with this ISBN already exists."
            });
        }

        res.status(500).json({
            message: "Unable to add book"
        });
    }
});

// Update a book
app.put("/api/books/:id", async (req, res) => {
    const { id } = req.params;

    const {
        title,
        author,
        isbn,
        publisher,
        total_copies,
        category_id
    } = req.body;

    if (!title || !author || !total_copies || total_copies < 1) {
        return res.status(400).json({
            message: "Title, author and valid total copies are required"
        });
    }

    try {
        const currentBook = await pool.query(
            `
            SELECT total_copies, available_copies
            FROM books
            WHERE id = $1
            `,
            [id]
        );

        if (currentBook.rows.length === 0) {
            return res.status(404).json({
                message: "Book not found"
            });
        }

        const oldTotal = currentBook.rows[0].total_copies;
        const oldAvailable = currentBook.rows[0].available_copies;

        const issuedCopies = oldTotal - oldAvailable;

        if (total_copies < issuedCopies) {
            return res.status(400).json({
                message:
                    `Cannot reduce copies below ${issuedCopies}. ` +
                    `Some copies are currently issued.`
            });
        }

        const newAvailable =
            total_copies - issuedCopies;

        const result = await pool.query(
            `
            UPDATE books
            SET
                title = $1,
                author = $2,
                isbn = $3,
                category_id = $4,
                publisher = $5,
                total_copies = $6,
                available_copies = $7
            WHERE id = $8
            RETURNING *
            `,
            [
                title,
                author,
                isbn || null,
                category_id || null,
                publisher || null,
                total_copies,
                newAvailable,
                id
            ]
        );

        res.json(result.rows[0]);

    } catch (error) {
        console.error("Update book error:", error);

        if (error.code === "23505") {
            return res.status(400).json({
                message: "A book with this ISBN already exists."
            });
        }

        res.status(500).json({
            message: "Unable to update book"
        });
    }
});
// Delete a book
app.delete("/api/books/:id", async (req, res) => {

    const { id } = req.params;

    try {

        const result = await pool.query(
            "DELETE FROM books WHERE id = $1 RETURNING *",
            [id]
        );

        if (result.rows.length === 0) {

            return res.status(404).json({
                message: "Book not found"
            });
        }

        res.json({
            success: true,
            message: "Book deleted successfully"
        });

    } catch (error) {

        console.error("Delete book error:", error);

        res.status(500).json({
            message: "Unable to delete book"
        });
    }
});
// Logout
app.post("/logout", (req, res) => {

    req.session.destroy((error) => {

        if (error) {
            console.error("Logout error:", error);

            return res.status(500).json({
                message: "Logout failed"
            });
        }

        res.json({
            success: true
        });
    });
});
// ==================== DASHBOARD API ====================

app.get("/api/dashboard", async (req, res) => {

    try {

        const booksResult = await pool.query(`
            SELECT
                COALESCE(SUM(total_copies), 0) AS total_books,
                COALESCE(SUM(available_copies), 0) AS available_books
            FROM books
        `);

        const issuedResult = await pool.query(`
            SELECT COUNT(*) AS issued_books
            FROM book_issues
            WHERE status = 'issued'
        `);

        const membersResult = await pool.query(`
            SELECT COUNT(*) AS total_members
            FROM students
        `);

        res.json({
            totalBooks: Number(booksResult.rows[0].total_books),
            availableBooks: Number(booksResult.rows[0].available_books),
            issuedBooks: Number(issuedResult.rows[0].issued_books),
            totalMembers: Number(membersResult.rows[0].total_members)
        });

    } catch (error) {

        console.error("Dashboard error:", error);

        res.status(500).json({
            message: "Unable to load dashboard statistics"
        });
    }
});
// ==================== STUDENT / MEMBER APIs ====================

// Get all members
app.get("/api/students", async (req, res) => {

    try {

        const result = await pool.query(`
            SELECT *
            FROM students
            ORDER BY id DESC
        `);

        res.json(result.rows);

    } catch (error) {

        console.error("Get students error:", error);

        res.status(500).json({
            message: "Unable to load members"
        });

    }

});


// Add member
app.post("/api/students", async (req, res) => {

    const {
        student_id,
        name,
        department,
        phone,
        email
    } = req.body;


    if (!student_id || !name) {

        return res.status(400).json({
            message: "Student ID and name are required"
        });

    }


    try {

        const result = await pool.query(
            `
            INSERT INTO students
            (student_id, name, department, phone, email)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            `,
            [
                student_id,
                name,
                department || null,
                phone || null,
                email || null
            ]
        );


        res.status(201).json(result.rows[0]);

    } catch (error) {

        console.error("Add student error:", error);


        if (error.code === "23505") {

            return res.status(400).json({
                message: "This Student ID already exists."
            });

        }


        res.status(500).json({
            message: "Unable to add member"
        });

    }

});


// Update member
app.put("/api/students/:id", async (req, res) => {

    const { id } = req.params;

    const {
        student_id,
        name,
        department,
        phone,
        email
    } = req.body;


    if (!student_id || !name) {

        return res.status(400).json({
            message: "Student ID and name are required"
        });

    }


    try {

        const result = await pool.query(
            `
            UPDATE students
            SET
                student_id = $1,
                name = $2,
                department = $3,
                phone = $4,
                email = $5
            WHERE id = $6
            RETURNING *
            `,
            [
                student_id,
                name,
                department || null,
                phone || null,
                email || null,
                id
            ]
        );


        if (result.rows.length === 0) {

            return res.status(404).json({
                message: "Member not found"
            });

        }


        res.json(result.rows[0]);

    } catch (error) {

        console.error("Update student error:", error);


        if (error.code === "23505") {

            return res.status(400).json({
                message: "This Student ID already exists."
            });

        }


        res.status(500).json({
            message: "Unable to update member"
        });

    }

});


// Delete member
app.delete("/api/students/:id", async (req, res) => {

    const { id } = req.params;


    try {

        const result = await pool.query(
            "DELETE FROM students WHERE id = $1 RETURNING *",
            [id]
        );


        if (result.rows.length === 0) {

            return res.status(404).json({
                message: "Member not found"
            });

        }


        res.json({
            success: true,
            message: "Member deleted successfully"
        });

    } catch (error) {

        console.error("Delete student error:", error);


        if (error.code === "23503") {

            return res.status(400).json({
                message: "This member has library transaction records and cannot be deleted."
            });

        }


        res.status(500).json({
            message: "Unable to delete member"
        });

    }

});
// ==================== ISSUE & RETURN APIs ====================

// Get currently issued books
app.get("/api/issues", async (req, res) => {

    try {

        const result = await pool.query(`
            SELECT
                book_issues.id,
                book_issues.issue_date,
                book_issues.due_date,
                books.title AS book_title,
                students.name AS student_name,
                students.student_id AS student_code
            FROM book_issues
            JOIN books
                ON book_issues.book_id = books.id
            JOIN students
                ON book_issues.student_id = students.id
            WHERE book_issues.status = 'issued'
            ORDER BY book_issues.id DESC
        `);

        res.json(result.rows);

    } catch (error) {

        console.error("Get issues error:", error);

        res.status(500).json({
            message: "Unable to load issued books"
        });

    }

});

// CATEGORY APIs

// Get all categories
app.get("/api/categories", async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT *
            FROM categories
            ORDER BY name ASC
        `);

        res.json(result.rows);
    } catch (error) {
        console.error("Get categories error:", error);
        res.status(500).json({
            message: "Unable to load categories"
        });
    }
});


// Add category
app.post("/api/categories", async (req, res) => {
    const { name, description } = req.body;

    if (!name || !name.trim()) {
        return res.status(400).json({
            message: "Category name is required"
        });
    }

    try {
        const result = await pool.query(
            `
            INSERT INTO categories
            (name, description)
            VALUES ($1, $2)
            RETURNING *
            `,
            [name.trim(), description || null]
        );

        res.status(201).json(result.rows[0]);

    } catch (error) {
        console.error("Add category error:", error);

        if (error.code === "23505") {
            return res.status(400).json({
                message: "This category already exists."
            });
        }

        res.status(500).json({
            message: "Unable to add category"
        });
    }
});


// Update category
app.put("/api/categories/:id", async (req, res) => {
    const { id } = req.params;
    const { name, description } = req.body;

    if (!name || !name.trim()) {
        return res.status(400).json({
            message: "Category name is required"
        });
    }

    try {
        const result = await pool.query(
            `
            UPDATE categories
            SET
                name = $1,
                description = $2
            WHERE id = $3
            RETURNING *
            `,
            [name.trim(), description || null, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                message: "Category not found"
            });
        }

        res.json(result.rows[0]);

    } catch (error) {
        console.error("Update category error:", error);

        if (error.code === "23505") {
            return res.status(400).json({
                message: "This category already exists."
            });
        }

        res.status(500).json({
            message: "Unable to update category"
        });
    }
});


// Delete category
app.delete("/api/categories/:id", async (req, res) => {
    const { id } = req.params;

    try {
        const result = await pool.query(
            `
            DELETE FROM categories
            WHERE id = $1
            RETURNING *
            `,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                message: "Category not found"
            });
        }

        res.json({
            success: true,
            message: "Category deleted successfully"
        });

    } catch (error) {
        console.error("Delete category error:", error);

        res.status(500).json({
            message: "Unable to delete category"
        });
    }
});
// Issue a book
app.post("/api/issues", async (req, res) => {

    const {
        book_id,
        student_id,
        due_date
    } = req.body;


    if (!book_id || !student_id || !due_date) {

        return res.status(400).json({
            message: "Book, member and due date are required"
        });

    }


    const client = await pool.connect();


    try {

        await client.query("BEGIN");


        // Check book availability
        const bookResult = await client.query(
            `
            SELECT id, available_copies
            FROM books
            WHERE id = $1
            FOR UPDATE
            `,
            [book_id]
        );


        if (bookResult.rows.length === 0) {

            await client.query("ROLLBACK");

            return res.status(404).json({
                message: "Book not found"
            });

        }


        const book = bookResult.rows[0];


        if (book.available_copies <= 0) {

            await client.query("ROLLBACK");

            return res.status(400).json({
                message: "No copies of this book are currently available"
            });

        }


        // Check member exists
        const studentResult = await client.query(
            "SELECT id FROM students WHERE id = $1",
            [student_id]
        );


        if (studentResult.rows.length === 0) {

            await client.query("ROLLBACK");

            return res.status(404).json({
                message: "Member not found"
            });

        }


        // Prevent same member from having the same book twice
        const existingIssue = await client.query(
            `
            SELECT id
            FROM book_issues
            WHERE book_id = $1
              AND student_id = $2
              AND status = 'issued'
            `,
            [book_id, student_id]
        );


        if (existingIssue.rows.length > 0) {

            await client.query("ROLLBACK");

            return res.status(400).json({
                message: "This member already has this book issued"
            });

        }


        // Create issue record
        const issueResult = await client.query(
            `
            INSERT INTO book_issues
            (book_id, student_id, due_date, status)
            VALUES ($1, $2, $3, 'issued')
            RETURNING *
            `,
            [
                book_id,
                student_id,
                due_date
            ]
        );


        // Decrease available copies
        await client.query(
            `
            UPDATE books
            SET available_copies = available_copies - 1
            WHERE id = $1
            `,
            [book_id]
        );


        await client.query("COMMIT");


        res.status(201).json({
            success: true,
            message: "Book issued successfully",
            issue: issueResult.rows[0]
        });


    } catch (error) {

        await client.query("ROLLBACK");

        console.error("Issue book error:", error);

        res.status(500).json({
            message: "Unable to issue book"
        });

    } finally {

        client.release();

    }

});


// Return a book
app.put("/api/issues/:id/return", async (req, res) => {

    const { id } = req.params;

    const client = await pool.connect();


    try {

        await client.query("BEGIN");


        // Find the issue
        const issueResult = await client.query(
            `
            SELECT *
            FROM book_issues
            WHERE id = $1
              AND status = 'issued'
            FOR UPDATE
            `,
            [id]
        );


        if (issueResult.rows.length === 0) {

            await client.query("ROLLBACK");

            return res.status(404).json({
                message: "Issued book record not found"
            });

        }


        const issue = issueResult.rows[0];


        // Calculate fine
        const today = new Date();

        const dueDate = new Date(issue.due_date);


        const todayOnly = new Date(
            today.getFullYear(),
            today.getMonth(),
            today.getDate()
        );


        const dueDateOnly = new Date(
            dueDate.getFullYear(),
            dueDate.getMonth(),
            dueDate.getDate()
        );


        const millisecondsPerDay =
            1000 * 60 * 60 * 24;


        const lateDays = Math.max(
            0,
            Math.ceil(
                (todayOnly - dueDateOnly) /
                millisecondsPerDay
            )
        );


        // Fine = ₹5 per late day
        const fine = lateDays * 5;


        // Update issue
        await client.query(
            `
            UPDATE book_issues
            SET
                return_date = CURRENT_DATE,
                fine = $1,
                status = 'returned'
            WHERE id = $2
            `,
            [fine, id]
        );


        // Increase available copies
        await client.query(
            `
            UPDATE books
            SET available_copies =
                LEAST(total_copies, available_copies + 1)
            WHERE id = $1
            `,
            [issue.book_id]
        );


        await client.query("COMMIT");


        res.json({
            success: true,
            message: "Book returned successfully",
            fine: fine,
            lateDays: lateDays
        });


    } catch (error) {

        await client.query("ROLLBACK");

        console.error("Return book error:", error);

        res.status(500).json({
            message: "Unable to return book"
        });

    } finally {

        client.release();

    }

});
// ISSUE HISTORY API
app.get("/api/issues/history", async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                book_issues.id,
                book_issues.issue_date,
                book_issues.due_date,
                book_issues.return_date,
                book_issues.fine,
                book_issues.status,
                books.title AS book_title,
                students.name AS student_name,
                students.student_id AS student_code
            FROM book_issues
            JOIN books
                ON book_issues.book_id = books.id
            JOIN students
                ON book_issues.student_id = students.id
            ORDER BY book_issues.id DESC
        `);

        res.json(result.rows);
    } catch (error) {
        console.error("Get issue history error:", error);
        res.status(500).json({
            message: "Unable to load issue history"
        });
    }
});
// Test database connection
app.get("/test-db", async (req, res) => {
    try {
        const result = await pool.query("SELECT NOW()");

        res.json({
            message: "Database connected successfully!",
            databaseTime: result.rows[0].now
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Database connection failed.");
    }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});