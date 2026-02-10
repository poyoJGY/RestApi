package me.jgy.api01.repository;

import me.jgy.api01.domain.Todo;
import me.jgy.api01.repository.search.TodoSearch;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TodoRepository extends JpaRepository<Todo, Long>, TodoSearch {
}
