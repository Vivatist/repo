package com.novavpn.tv.ui

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.key.*
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.novavpn.tv.BuildConfig
import com.novavpn.tv.R
import com.novavpn.tv.domain.model.ConnectionState

// Цвета NovaVPN
private val NovaBg = Color(0xFF121212)
private val NovaSurface = Color(0xFF1E1E1E)
private val NovaPrimary = Color(0xFF1E88E5)
private val NovaAccent = Color(0xFF00E676)
private val NovaError = Color(0xFFEF5350)
private val NovaYellow = Color(0xFFFFAB40)
private val NovaTextPrimary = Color(0xFFFFFFFF)
private val NovaTextSecondary = Color(0xB3FFFFFF)
private val NovaTextHint = Color(0x80FFFFFF)

/**
 * Главный экран NovaVPN для Android TV.
 *
 * Особенности TV-адаптации:
 * - Фокус по умолчанию на главной кнопке (подключиться/отключиться)
 * - Текстовые поля НЕ открывают клавиатуру при фокусе D-pad
 * - Клавиатура появляется только по нажатию Enter/Select на поле
 * - IME Done корректно выходит из режима редактирования (не закрывает приложение)
 * - Поле сбрасывает режим редактирования при потере фокуса
 * - Валидация при сохранении настроек
 * - Показ/скрытие пароля (компактная кнопка-иконка)
 */
@Composable
fun NovaVpnScreen(
    uiState: MainUiState,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onServerAddrChange: (String) -> Unit,
    onEmailChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onToggleSettings: () -> Unit,
    onSaveSettings: () -> Unit,
    onClearError: () -> Unit
) {
    // FocusRequester для главной кнопки — фокус при открытии
    val connectButtonFocusRequester = remember { FocusRequester() }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(NovaBg),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(48.dp)
        ) {
            // Логотип и название
            Text(
                text = "🛡",
                fontSize = 64.sp,
                modifier = Modifier.padding(bottom = 8.dp)
            )
            Text(
                text = "NovaVPN",
                color = NovaTextPrimary,
                fontSize = 36.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Статус подключения
            StatusDisplay(state = uiState.connectionState)

            Spacer(modifier = Modifier.height(32.dp))

            // Кнопка подключения/отключения
            ConnectButton(
                state = uiState.connectionState,
                onConnect = onConnect,
                onDisconnect = onDisconnect,
                focusRequester = connectButtonFocusRequester
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Кнопка настроек
            TvButton(
                text = if (uiState.showSettings) "Скрыть настройки" else "⚙ Настройки",
                onClick = onToggleSettings,
                backgroundColor = NovaSurface
            )

            // Панель настроек
            AnimatedVisibility(
                visible = uiState.showSettings,
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut()
            ) {
                SettingsPanel(
                    serverAddr = uiState.serverAddr,
                    email = uiState.email,
                    password = uiState.password,
                    validationError = uiState.validationError,
                    onServerAddrChange = onServerAddrChange,
                    onEmailChange = onEmailChange,
                    onPasswordChange = onPasswordChange,
                    onSave = onSaveSettings
                )
            }

            // Сообщение об ошибке подключения
            uiState.errorMessage?.let { error ->
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = error,
                    color = NovaError,
                    fontSize = 16.sp,
                    textAlign = TextAlign.Center
                )
            }
        }
    }

    // Запрос фокуса на главную кнопку при открытии экрана
    LaunchedEffect(Unit) {
        connectButtonFocusRequester.requestFocus()
    }

    // Перевод фокуса на кнопку подключения при закрытии панели настроек
    LaunchedEffect(uiState.showSettings) {
        if (!uiState.showSettings) {
            connectButtonFocusRequester.requestFocus()
        }
    }
}

/**
 * Отображение текущего статуса подключения с цветным индикатором.
 */
@Composable
private fun StatusDisplay(state: ConnectionState) {
    val (color, text) = when (state) {
        ConnectionState.DISCONNECTED -> Pair(NovaError, "Отключён")
        ConnectionState.CONNECTING -> Pair(NovaYellow, "Подключение…")
        ConnectionState.CONNECTED -> Pair(NovaAccent, "Подключён")
        ConnectionState.DISCONNECTING -> Pair(NovaYellow, "Отключение…")
    }

    val animatedAlpha by rememberInfiniteTransition(label = "pulse").animateFloat(
        initialValue = 1f,
        targetValue = 0.4f,
        animationSpec = infiniteRepeatable(
            animation = tween(800),
            repeatMode = RepeatMode.Reverse
        ),
        label = "alpha"
    )

    val displayAlpha = if (state == ConnectionState.CONNECTING || state == ConnectionState.DISCONNECTING) {
        animatedAlpha
    } else {
        1f
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center
    ) {
        Box(
            modifier = Modifier
                .size(16.dp)
                .clip(CircleShape)
                .background(color.copy(alpha = displayAlpha))
        )
        Spacer(modifier = Modifier.width(12.dp))
        Text(
            text = text,
            color = color.copy(alpha = displayAlpha),
            fontSize = 24.sp,
            fontWeight = FontWeight.Medium
        )
    }
}

/**
 * Кнопка подключения/отключения.
 */
@Composable
private fun ConnectButton(
    state: ConnectionState,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    focusRequester: FocusRequester = remember { FocusRequester() }
) {
    val isTransitioning = state == ConnectionState.CONNECTING || state == ConnectionState.DISCONNECTING

    val buttonText = when (state) {
        ConnectionState.DISCONNECTED -> "Подключиться"
        ConnectionState.CONNECTING -> "Подключение…"
        ConnectionState.CONNECTED -> "Отключиться"
        ConnectionState.DISCONNECTING -> "Отключение…"
    }

    val buttonColor = when (state) {
        ConnectionState.DISCONNECTED -> NovaPrimary
        ConnectionState.CONNECTING -> NovaYellow
        ConnectionState.CONNECTED -> NovaAccent
        ConnectionState.DISCONNECTING -> NovaYellow
    }

    TvButton(
        text = buttonText,
        onClick = {
            when (state) {
                ConnectionState.DISCONNECTED -> onConnect()
                ConnectionState.CONNECTED -> onDisconnect()
                else -> {}
            }
        },
        backgroundColor = buttonColor,
        enabled = !isTransitioning,
        modifier = Modifier
            .width(320.dp)
            .height(64.dp),
        externalFocusRequester = focusRequester
    )
}

/**
 * Кнопка, адаптированная для D-pad навигации на Android TV.
 */
@Composable
private fun TvButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    backgroundColor: Color = NovaPrimary,
    enabled: Boolean = true,
    externalFocusRequester: FocusRequester? = null
) {
    val internalFocusRequester = remember { FocusRequester() }
    val focusRequester = externalFocusRequester ?: internalFocusRequester
    var isFocused by remember { mutableStateOf(false) }

    val bgColor = if (isFocused) backgroundColor.copy(alpha = 1f) else backgroundColor.copy(alpha = 0.7f)
    val borderColor = if (isFocused) NovaTextPrimary else Color.Transparent

    Box(
        modifier = modifier
            .then(Modifier.defaultMinSize(minWidth = 200.dp, minHeight = 48.dp))
            .clip(RoundedCornerShape(12.dp))
            .background(if (enabled) bgColor else bgColor.copy(alpha = 0.4f))
            .border(2.dp, borderColor, RoundedCornerShape(12.dp))
            .focusRequester(focusRequester)
            .onFocusChanged { isFocused = it.isFocused }
            .focusable(enabled)
            .onKeyEvent { event ->
                if (event.type == KeyEventType.KeyUp &&
                    (event.key == Key.Enter || event.key == Key.DirectionCenter)
                ) {
                    if (enabled) onClick()
                    true
                } else false
            },
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = text,
            color = if (enabled) NovaTextPrimary else NovaTextSecondary,
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 12.dp)
        )
    }
}

/**
 * Панель настроек подключения.
 */
@Composable
private fun SettingsPanel(
    serverAddr: String,
    email: String,
    password: String,
    validationError: String?,
    onServerAddrChange: (String) -> Unit,
    onEmailChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onSave: () -> Unit
) {
    var passwordVisible by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .padding(top = 16.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(NovaSurface)
            .padding(24.dp)
            .width(400.dp)
    ) {
        Text(
            text = "Настройки подключения",
            color = NovaTextPrimary,
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(bottom = 16.dp)
        )

        // Поле сервера
        TvEditableField(
            value = serverAddr,
            onValueChange = onServerAddrChange,
            label = "Сервер (host:port)",
            placeholder = "212.118.43.43:443"
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Поле email
        TvEditableField(
            value = email,
            onValueChange = onEmailChange,
            label = "Email",
            placeholder = "user@example.com"
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Поле пароля с кнопкой показать/скрыть
        Row(
            verticalAlignment = Alignment.Bottom,
            modifier = Modifier.fillMaxWidth()
        ) {
            // Поле пароля
            Box(modifier = Modifier.weight(1f)) {
                TvEditableField(
                    value = password,
                    onValueChange = onPasswordChange,
                    label = "Пароль",
                    placeholder = "••••••••",
                    isPassword = true,
                    passwordVisible = passwordVisible
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Квадратная кнопка показать/скрыть пароль (только иконка глаза)
            EyeToggleButton(
                passwordVisible = passwordVisible,
                onToggle = { passwordVisible = !passwordVisible }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Ошибка валидации
        validationError?.let { error ->
            Text(
                text = error,
                color = NovaError,
                fontSize = 14.sp,
                modifier = Modifier.padding(bottom = 8.dp)
            )
        }

        // Кнопка сохранить
        TvButton(
            text = "Сохранить",
            onClick = onSave,
            backgroundColor = NovaPrimary,
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Версия приложения
        Text(
            text = "NovaVPN v${BuildConfig.VERSION_NAME}",
            color = NovaTextSecondary.copy(alpha = 0.4f),
            fontSize = 12.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

/**
 * Поле ввода для Android TV с двухрежимной логикой.
 *
 * Режим просмотра: D-pad фокусирует поле БЕЗ открытия клавиатуры.
 * Режим редактирования: Enter/Select → клавиатура открывается.
 * Back / IME Done / Enter → выход из редактирования.
 * Потеря фокуса → автоматический выход из редактирования.
 */
@Composable
private fun TvEditableField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    placeholder: String = "",
    isPassword: Boolean = false,
    passwordVisible: Boolean = false
) {
    var isFocused by remember { mutableStateOf(false) }
    var isEditing by remember { mutableStateOf(false) }
    // Флаг для восстановления фокуса ПОСЛЕ рекомпозиции
    // (нельзя вызывать focusRequester.requestFocus() на view-mode Box,
    // пока он ещё не в composition tree)
    var shouldRestoreFocus by remember { mutableStateOf(false) }
    val focusRequester = remember { FocusRequester() }
    val editFocusRequester = remember { FocusRequester() }
    val keyboardController = LocalSoftwareKeyboardController.current

    val shouldHide = isPassword && !passwordVisible

    // Функция выхода из режима редактирования
    val exitEditing = {
        isEditing = false
        keyboardController?.hide()
        // НЕ вызываем focusRequester.requestFocus() здесь!
        // View-mode Box ещё не существует (мы в if-ветке).
        // Вместо этого ставим флаг — LaunchedEffect в else-ветке
        // восстановит фокус после рекомпозиции.
        shouldRestoreFocus = true
    }

    Column {
        Text(
            text = label,
            color = if (isFocused || isEditing) NovaPrimary else NovaTextSecondary,
            fontSize = 14.sp,
            fontWeight = if (isFocused || isEditing) FontWeight.Medium else FontWeight.Normal,
            modifier = Modifier.padding(bottom = 4.dp)
        )

        if (isEditing) {
            // Флаг: фокус был получен хотя бы раз.
            // Нужен чтобы onFocusChanged не срабатывал при первом рендере
            // (BasicTextField создаётся без фокуса → onFocusChanged(false) → мгновенный откат)
            var editFocusAcquired by remember { mutableStateOf(false) }

            // Режим редактирования — BasicTextField с клавиатурой
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                textStyle = TextStyle(
                    color = NovaTextPrimary,
                    fontSize = 18.sp
                ),
                cursorBrush = SolidColor(NovaPrimary),
                visualTransformation = if (shouldHide) PasswordVisualTransformation() else VisualTransformation.None,
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(
                    onDone = { exitEditing() }
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(NovaBg)
                    .border(2.dp, NovaPrimary, RoundedCornerShape(8.dp))
                    .focusRequester(editFocusRequester)
                    .onFocusChanged { state ->
                        if (state.isFocused) {
                            // Фокус получен — запоминаем
                            editFocusAcquired = true
                        } else if (editFocusAcquired && isEditing) {
                            // Фокус был и ушёл (D-pad навигация) — выходим
                            isEditing = false
                            keyboardController?.hide()
                        }
                    }
                    .onKeyEvent { event ->
                        if (event.type == KeyEventType.KeyUp) {
                            when (event.key) {
                                Key.Back -> {
                                    exitEditing()
                                    true
                                }
                                // Enter/DirectionCenter ПОГЛОЩАЕМ, но НЕ выходим.
                                // Выход по галочке IME — через keyboardActions.onDone.
                                // Если не поглотить — событие пробросится в Activity
                                // и приложение закроется.
                                Key.Enter, Key.DirectionCenter -> true
                                else -> false
                            }
                        } else if (event.type == KeyEventType.KeyDown) {
                            // KeyDown тоже поглощаем для Enter/DirectionCenter
                            when (event.key) {
                                Key.Enter, Key.DirectionCenter -> true
                                else -> false
                            }
                        } else false
                    }
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                decorationBox = { innerTextField ->
                    Box {
                        if (value.isEmpty()) {
                            Text(
                                text = placeholder,
                                color = NovaTextHint,
                                fontSize = 18.sp
                            )
                        }
                        innerTextField()
                    }
                }
            )

            // Фокус и клавиатура при входе в режим редактирования
            LaunchedEffect(Unit) {
                editFocusRequester.requestFocus()
                keyboardController?.show()
            }
        } else {
            // Восстановление фокуса после выхода из режима редактирования.
            // LaunchedEffect срабатывает ПОСЛЕ того, как view-mode Box
            // появился в composition tree и focusRequester привязан к нему.
            LaunchedEffect(shouldRestoreFocus) {
                if (shouldRestoreFocus) {
                    focusRequester.requestFocus()
                    shouldRestoreFocus = false
                }
            }

            // Режим просмотра — focusable-контейнер, клавиатура НЕ появляется
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(NovaBg)
                    .border(
                        width = if (isFocused) 2.dp else 1.dp,
                        color = if (isFocused) NovaPrimary else NovaTextSecondary.copy(alpha = 0.3f),
                        shape = RoundedCornerShape(8.dp)
                    )
                    .focusRequester(focusRequester)
                    .onFocusChanged { isFocused = it.isFocused }
                    .focusable()
                    .onKeyEvent { event ->
                        if (event.type == KeyEventType.KeyUp &&
                            (event.key == Key.Enter || event.key == Key.DirectionCenter)
                        ) {
                            isEditing = true
                            true
                        } else false
                    }
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                contentAlignment = Alignment.CenterStart
            ) {
                val displayText = when {
                    value.isEmpty() -> placeholder
                    shouldHide -> "•".repeat(value.length.coerceAtMost(20))
                    else -> value
                }
                val textColor = if (value.isEmpty()) NovaTextHint else NovaTextPrimary

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = displayText,
                        color = textColor,
                        fontSize = 18.sp,
                        modifier = Modifier.weight(1f)
                    )
                    if (isFocused) {
                        Text(
                            text = "✎",
                            color = NovaPrimary,
                            fontSize = 16.sp
                        )
                    }
                }
            }
        }
    }
}

/**
 * Квадратная кнопка-иконка глаза для переключения видимости пароля.
 * Компактная, без текста — только пиктограмма.
 */
@Composable
private fun EyeToggleButton(
    passwordVisible: Boolean,
    onToggle: () -> Unit
) {
    val focusRequester = remember { FocusRequester() }
    var isFocused by remember { mutableStateOf(false) }

    val borderColor = if (isFocused) NovaPrimary else Color.Transparent

    Box(
        modifier = Modifier
            .size(48.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(if (isFocused) NovaSurface else NovaBg)
            .border(2.dp, borderColor, RoundedCornerShape(8.dp))
            .focusRequester(focusRequester)
            .onFocusChanged { isFocused = it.isFocused }
            .focusable()
            .onKeyEvent { event ->
                if (event.type == KeyEventType.KeyUp &&
                    (event.key == Key.Enter || event.key == Key.DirectionCenter)
                ) {
                    onToggle()
                    true
                } else false
            },
        contentAlignment = Alignment.Center
    ) {
        Icon(
            painter = painterResource(id = R.drawable.ic_eye),
            contentDescription = if (passwordVisible) "Скрыть пароль" else "Показать пароль",
            tint = if (passwordVisible) NovaPrimary else NovaTextSecondary,
            modifier = Modifier.size(22.dp)
        )
    }
}
