import React, { useState } from 'react';

function TodoList() {
  const [todos, setTodos] = useState([]);

  const addTodo = () => {
    setTodos([...todos, { id: todos.length, text: 'New Todo' }]);
  };

  return (
    <div>
      <button onClick={addTodo}>Add Todo</button>
      <ul>
        {todos.map((todo) => (
          <li key={todo.id}>{todo.text}</li>
        ))}
      </ul>
    </div>
  );
}

export default TodoList;
