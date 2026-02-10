package me.jgy.api01.service;

import jakarta.transaction.Transactional;
import me.jgy.api01.dto.PageRequestDTO;
import me.jgy.api01.dto.PageResponseDTO;
import me.jgy.api01.dto.TodoDTO;

@Transactional
public interface TodoService {

    Long register(TodoDTO todoDTO);
    TodoDTO read(Long tno);
    PageResponseDTO<TodoDTO> list(PageRequestDTO pageRequestDTO);
    void remove(Long tno);
    void modify(TodoDTO todoDTO);
}
