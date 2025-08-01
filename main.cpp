
#include <QtWidgets>
#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QTabWidget>
#include <QTextEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QSplitter>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QProgressBar>
#include <QScrollArea>
#include <QGroupBox>
#include <QMessageBox>
#include <QTimer>
#include <QProcess>
#include <QFileDialog>
#include <QMenuBar>
#include <QStatusBar>
#include <QTextBrowser> 
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>

class CodeEditor : public QPlainTextEdit {
    Q_OBJECT
public:
    CodeEditor(QWidget *parent = nullptr) : QPlainTextEdit(parent) {
        setFont(QFont("Courier New", 12));
        setTabStopDistance(40);
        setStyleSheet("QPlainTextEdit { background-color: #2b2b2b; color: #ffffff; }");
    }
};

class LessonContent {
public:
    QString title;
    QString description;
    QString code;
    QString explanation;
    QString expectedOutput;
    
    LessonContent(const QString& t, const QString& d, const QString& c, const QString& e, const QString& o)
        : title(t), description(d), code(c), explanation(e), expectedOutput(o) {}
};

class CppLearningPlatform : public QMainWindow {
    Q_OBJECT

private:
    QTabWidget* mainTabs;
    QTreeWidget* lessonTree;
    QTextBrowser* lessonContent;
    CodeEditor* codeEditor;
    QTextEdit* outputArea;
    QPushButton* runButton;
    QPushButton* resetButton;
    QPushButton* nextButton;
    QProgressBar* progressBar;
    QLabel* statusLabel;
    QComboBox* difficultyCombo;
    
    std::vector<std::vector<LessonContent>> lessons;
    int currentDifficulty = 0;
    int currentLesson = 0;
    int completedLessons = 0;

public:
    CppLearningPlatform(QWidget *parent = nullptr) : QMainWindow(parent) {
        setupUI();
        setupLessons();
        loadLesson(0, 0);
    }

private slots:
    void onLessonSelected(QTreeWidgetItem* item, int column);
    void onRunCode();
    void onResetCode();
    void onNextLesson();
    void onDifficultyChanged(int index);

private:
    void setupUI() {
        setWindowTitle("C++ Learning Platform");
        setMinimumSize(1200, 800);
        
        // Central widget
        QWidget* centralWidget = new QWidget;
        setCentralWidget(centralWidget);
        
        // Main layout
        QHBoxLayout* mainLayout = new QHBoxLayout(centralWidget);
        
        // Left panel - Lessons tree
        QWidget* leftPanel = new QWidget;
        leftPanel->setMaximumWidth(300);
        leftPanel->setMinimumWidth(250);
        QVBoxLayout* leftLayout = new QVBoxLayout(leftPanel);
        
        // Difficulty selector
        QLabel* difficultyLabel = new QLabel("Difficulty Level:");
        difficultyCombo = new QComboBox;
        difficultyCombo->addItems({"Beginner", "Intermediate", "Advanced"});
        connect(difficultyCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), 
                this, &CppLearningPlatform::onDifficultyChanged);
        
        // Progress bar
        progressBar = new QProgressBar;
        progressBar->setRange(0, 100);
        
        // Lessons tree
        lessonTree = new QTreeWidget;
        lessonTree->setHeaderLabel("Lessons");
        connect(lessonTree, &QTreeWidget::itemClicked, 
                this, &CppLearningPlatform::onLessonSelected);
        
        leftLayout->addWidget(difficultyLabel);
        leftLayout->addWidget(difficultyCombo);
        leftLayout->addWidget(new QLabel("Progress:"));
        leftLayout->addWidget(progressBar);
        leftLayout->addWidget(lessonTree);
        
        // Right panel - Content and editor
        QSplitter* rightSplitter = new QSplitter(Qt::Vertical);
        
        // Top part - Lesson content
        QWidget* contentWidget = new QWidget;
        QVBoxLayout* contentLayout = new QVBoxLayout(contentWidget);
        
        lessonContent = new QTextBrowser;
        lessonContent->setMaximumHeight(200);
        contentLayout->addWidget(new QLabel("Lesson Content:"));
        contentLayout->addWidget(lessonContent);
        
        // Middle part - Code editor
        QWidget* editorWidget = new QWidget;
        QVBoxLayout* editorLayout = new QVBoxLayout(editorWidget);
        
        QHBoxLayout* buttonLayout = new QHBoxLayout;
        runButton = new QPushButton("Run Code");
        resetButton = new QPushButton("Reset");
        nextButton = new QPushButton("Next Lesson");
        
        connect(runButton, &QPushButton::clicked, this, &CppLearningPlatform::onRunCode);
        connect(resetButton, &QPushButton::clicked, this, &CppLearningPlatform::onResetCode);
        connect(nextButton, &QPushButton::clicked, this, &CppLearningPlatform::onNextLesson);
        
        buttonLayout->addWidget(runButton);
        buttonLayout->addWidget(resetButton);
        buttonLayout->addWidget(nextButton);
        buttonLayout->addStretch();
        
        codeEditor = new CodeEditor;
        
        editorLayout->addWidget(new QLabel("Code Editor:"));
        editorLayout->addLayout(buttonLayout);
        editorLayout->addWidget(codeEditor);
        
        // Bottom part - Output
        QWidget* outputWidget = new QWidget;
        QVBoxLayout* outputLayout = new QVBoxLayout(outputWidget);
        
        outputArea = new QTextEdit;
        outputArea->setMaximumHeight(150);
        outputArea->setReadOnly(true);
        outputArea->setStyleSheet("QTextEdit { background-color: #1e1e1e; color: #00ff00; font-family: 'Courier New'; }");
        
        outputLayout->addWidget(new QLabel("Output:"));
        outputLayout->addWidget(outputArea);
        
        rightSplitter->addWidget(contentWidget);
        rightSplitter->addWidget(editorWidget);
        rightSplitter->addWidget(outputWidget);
        rightSplitter->setStretchFactor(0, 1);
        rightSplitter->setStretchFactor(1, 3);
        rightSplitter->setStretchFactor(2, 1);
        
        mainLayout->addWidget(leftPanel,    /*stretch=*/1);
        mainLayout->addWidget(rightSplitter,/*stretch=*/4);
        
        // Status bar
        statusLabel = new QLabel("Ready");
        statusBar()->addWidget(statusLabel);
        
        // Menu bar
        createMenuBar();
    }
    
    void createMenuBar() {
        QMenuBar* menuBar = this->menuBar();
        
        QMenu* fileMenu = menuBar->addMenu("File");
        fileMenu->addAction("Save Code", [this]() {
            QString fileName = QFileDialog::getSaveFileName(this, "Save Code", "", "C++ Files (*.cpp)");
            if (!fileName.isEmpty()) {
                QFile file(fileName);
                if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                    QTextStream out(&file);
                    out << codeEditor->toPlainText();
                }
            }
        });
        
        QMenu* helpMenu = menuBar->addMenu("Help");
        helpMenu->addAction("About", [this]() {
            QMessageBox::about(this, "About", "C++ Learning Platform\nLearn C++ from basics to advanced concepts!");
        });
    }
    
    void setupLessons() {
        // Beginner lessons
        std::vector<LessonContent> beginnerLessons = {
            LessonContent(
                "Hello World",
                "Your first C++ program! This lesson introduces the basic structure of a C++ program.",
                "#include <iostream>\nusing namespace std;\n\nint main() {\n    cout << \"Hello, World!\" << endl;\n    return 0;\n}",
                "Every C++ program starts with the main() function. #include <iostream> allows us to use input/output operations. cout is used to display output.",
                "Hello, World!"
            ),
            LessonContent(
                "Variables and Data Types",
                "Learn about different data types in C++: int, float, double, char, bool.",
                "#include <iostream>\nusing namespace std;\n\nint main() {\n    int age = 25;\n    float height = 5.9;\n    char grade = 'A';\n    bool isStudent = true;\n    \n    cout << \"Age: \" << age << endl;\n    cout << \"Height: \" << height << endl;\n    cout << \"Grade: \" << grade << endl;\n    cout << \"Is Student: \" << isStudent << endl;\n    \n    return 0;\n}",
                "Variables store data. int stores whole numbers, float stores decimal numbers, char stores single characters, and bool stores true/false values.",
                "Age: 25\nHeight: 5.9\nGrade: A\nIs Student: 1"
            ),
            LessonContent(
                "Input and Output",
                "Learn how to get input from users using cin and display output using cout.",
                "#include <iostream>\nusing namespace std;\n\nint main() {\n    string name;\n    int age;\n    \n    cout << \"Enter your name: \";\n    cin >> name;\n    cout << \"Enter your age: \";\n    cin >> age;\n    \n    cout << \"Hello \" << name << \", you are \" << age << \" years old!\" << endl;\n    \n    return 0;\n}",
                "cin is used to read input from the user. We can read different types of data and use them in our program.",
                "Enter your name: John\nEnter your age: 20\nHello John, you are 20 years old!"
            )
        };
        
        // Intermediate lessons
        std::vector<LessonContent> intermediateLessons = {
            LessonContent(
                "Functions",
                "Learn how to create and use functions to organize your code.",
                "#include <iostream>\nusing namespace std;\n\nint add(int a, int b) {\n    return a + b;\n}\n\nint main() {\n    int x = 5, y = 3;\n    int result = add(x, y);\n    cout << x << \" + \" << y << \" = \" << result << endl;\n    return 0;\n}",
                "Functions help organize code into reusable blocks. They can take parameters and return values.",
                "5 + 3 = 8"
            ),
            LessonContent(
                "Arrays",
                "Learn about arrays - collections of elements of the same type.",
                "#include <iostream>\nusing namespace std;\n\nint main() {\n    int numbers[5] = {1, 2, 3, 4, 5};\n    \n    cout << \"Array elements: \";\n    for(int i = 0; i < 5; i++) {\n        cout << numbers[i] << \" \";\n    }\n    cout << endl;\n    \n    return 0;\n}",
                "Arrays store multiple values of the same type. We use indices (0, 1, 2...) to access elements.",
                "Array elements: 1 2 3 4 5"
            ),
            LessonContent(
                "Loops",
                "Learn about for, while, and do-while loops for repetitive tasks.",
                "#include <iostream>\nusing namespace std;\n\nint main() {\n    // For loop\n    cout << \"For loop: \";\n    for(int i = 1; i <= 5; i++) {\n        cout << i << \" \";\n    }\n    cout << endl;\n    \n    // While loop\n    cout << \"While loop: \";\n    int j = 1;\n    while(j <= 5) {\n        cout << j << \" \";\n        j++;\n    }\n    cout << endl;\n    \n    return 0;\n}",
                "Loops allow us to repeat code. For loops are great when you know how many times to repeat, while loops continue until a condition becomes false.",
                "For loop: 1 2 3 4 5\nWhile loop: 1 2 3 4 5"
            )
        };
        
        // Advanced lessons
        std::vector<LessonContent> advancedLessons = {
            LessonContent(
                "Classes and Objects",
                "Learn about Object-Oriented Programming with classes and objects.",
                "#include <iostream>\nusing namespace std;\n\nclass Rectangle {\npublic:\n    int width, height;\n    \n    Rectangle(int w, int h) {\n        width = w;\n        height = h;\n    }\n    \n    int area() {\n        return width * height;\n    }\n};\n\nint main() {\n    Rectangle rect(5, 3);\n    cout << \"Area: \" << rect.area() << endl;\n    return 0;\n}",
                "Classes are blueprints for objects. They contain data (attributes) and functions (methods) that work with that data.",
                "Area: 15"
            ),
            LessonContent(
                "Pointers",
                "Learn about pointers - variables that store memory addresses.",
                "#include <iostream>\nusing namespace std;\n\nint main() {\n    int x = 42;\n    int* ptr = &x;\n    \n    cout << \"Value of x: \" << x << endl;\n    cout << \"Address of x: \" << &x << endl;\n    cout << \"Value of ptr: \" << ptr << endl;\n    cout << \"Value pointed by ptr: \" << *ptr << endl;\n    \n    return 0;\n}",
                "Pointers store memory addresses. & gets the address of a variable, * dereferences a pointer to get the value at that address.",
                "Value of x: 42\nAddress of x: 0x...\nValue of ptr: 0x...\nValue pointed by ptr: 42"
            ),
            LessonContent(
                "Templates",
                "Learn about templates for generic programming.",
                "#include <iostream>\nusing namespace std;\n\ntemplate<typename T>\nT maximum(T a, T b) {\n    return (a > b) ? a : b;\n}\n\nint main() {\n    cout << \"Max of 5 and 3: \" << maximum(5, 3) << endl;\n    cout << \"Max of 5.5 and 3.2: \" << maximum(5.5, 3.2) << endl;\n    cout << \"Max of 'a' and 'z': \" << maximum('a', 'z') << endl;\n    \n    return 0;\n}",
                "Templates allow you to write functions and classes that work with any data type. The compiler generates specific versions for each type used.",
                "Max of 5 and 3: 5\nMax of 5.5 and 3.2: 5.5\nMax of 'a' and 'z': z"
            )
        };
        
        lessons.push_back(beginnerLessons);
        lessons.push_back(intermediateLessons);
        lessons.push_back(advancedLessons);
        
        updateLessonTree();
    }
    
    void updateLessonTree() {
        lessonTree->clear();
        
        QStringList difficultyNames = {"Beginner", "Intermediate", "Advanced"};
        
        for(int d = 0; d < lessons.size(); d++) {
            QTreeWidgetItem* difficultyItem = new QTreeWidgetItem(lessonTree);
            difficultyItem->setText(0, difficultyNames[d]);
            difficultyItem->setData(0, Qt::UserRole, -1); // -1 indicates difficulty level
            
            for(int l = 0; l < lessons[d].size(); l++) {
                QTreeWidgetItem* lessonItem = new QTreeWidgetItem(difficultyItem);
                lessonItem->setText(0, QString("%1. %2").arg(l + 1).arg(lessons[d][l].title));
                lessonItem->setData(0, Qt::UserRole, l);
                lessonItem->setData(1, Qt::UserRole, d);
            }
        }
        
        lessonTree->expandAll();
    }
    
    void loadLesson(int difficulty, int lesson) {
        if(difficulty >= lessons.size() || lesson >= lessons[difficulty].size()) return;
        
        currentDifficulty = difficulty;
        currentLesson = lesson;
        
        const LessonContent& content = lessons[difficulty][lesson];
        
        QString htmlContent = QString(
            "<h2>%1</h2>"
            "<p><b>Description:</b> %2</p>"
            "<p><b>Explanation:</b> %3</p>"
            "<p><b>Expected Output:</b></p>"
            "<pre style='background-color: #f0f0f0; padding: 10px;'>%4</pre>"
        ).arg(content.title).arg(content.description).arg(content.explanation).arg(content.expectedOutput);
        
        lessonContent->setHtml(htmlContent);
        codeEditor->setPlainText(content.code);
        outputArea->clear();
        
        statusLabel->setText(QString("Lesson %1.%2: %3").arg(difficulty + 1).arg(lesson + 1).arg(content.title));
        
        // Update progress
        int totalLessons = 0;
        for(const auto& diffLessons : lessons) {
            totalLessons += diffLessons.size();
        }
        
        int currentProgress = 0;
        for(int d = 0; d < difficulty; d++) {
            currentProgress += lessons[d].size();
        }
        currentProgress += lesson;
        
        progressBar->setValue((currentProgress * 100) / totalLessons);
    }
};

void CppLearningPlatform::onLessonSelected(QTreeWidgetItem* item, int column) {
    int lessonIndex = item->data(0, Qt::UserRole).toInt();
    int difficultyIndex = item->data(1, Qt::UserRole).toInt();
    
    if(lessonIndex >= 0 && difficultyIndex >= 0) {
        loadLesson(difficultyIndex, lessonIndex);
    }
}

void CppLearningPlatform::onRunCode() {
    QString code = codeEditor->toPlainText();
    
    // Save code to temporary file
    QFile tempFile("temp_code.cpp");
    if(tempFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&tempFile);
        out << code;
        tempFile.close();
        
        // Compile and run
        QProcess* process = new QProcess(this);
        process->start("g++", QStringList() << "-o" << "temp_program" << "temp_code.cpp");
        process->waitForFinished();
        
        if(process->exitCode() == 0) {
            // Compilation successful, run the program
            QProcess* runProcess = new QProcess(this);
            runProcess->start("./temp_program");
            runProcess->waitForFinished();
            
            QString output = runProcess->readAllStandardOutput();
            QString error = runProcess->readAllStandardError();
            
            if(!output.isEmpty()) {
                outputArea->setText(output);
                outputArea->setStyleSheet("QTextEdit { background-color: #1e1e1e; color: #00ff00; font-family: 'Courier New'; }");
            }
            if(!error.isEmpty()) {
                outputArea->setText(error);
                outputArea->setStyleSheet("QTextEdit { background-color: #1e1e1e; color: #ff0000; font-family: 'Courier New'; }");
            }
            
            delete runProcess;
        } else {
            // Compilation error
            QString error = process->readAllStandardError();
            outputArea->setText("Compilation Error:\n" + error);
            outputArea->setStyleSheet("QTextEdit { background-color: #1e1e1e; color: #ff0000; font-family: 'Courier New'; }");
        }
        
        delete process;
    }
}

void CppLearningPlatform::onResetCode() {
    if(currentDifficulty < lessons.size() && currentLesson < lessons[currentDifficulty].size()) {
        codeEditor->setPlainText(lessons[currentDifficulty][currentLesson].code);
        outputArea->clear();
    }
}

void CppLearningPlatform::onNextLesson() {
    int nextLesson = currentLesson + 1;
    int nextDifficulty = currentDifficulty;
    
    if(nextLesson >= lessons[currentDifficulty].size()) {
        nextLesson = 0;
        nextDifficulty++;
        if(nextDifficulty >= lessons.size()) {
            QMessageBox::information(this, "Congratulations!", "You have completed all lessons!");
            return;
        }
    }
    
    loadLesson(nextDifficulty, nextLesson);
    
    // Update difficulty combo if needed
    if(nextDifficulty != currentDifficulty) {
        difficultyCombo->setCurrentIndex(nextDifficulty);
    }
}

void CppLearningPlatform::onDifficultyChanged(int index) {
    currentDifficulty = index;
    loadLesson(index, 0);
}

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    CppLearningPlatform platform;
    platform.show();
    
    return app.exec();
}

#include "main.moc"
